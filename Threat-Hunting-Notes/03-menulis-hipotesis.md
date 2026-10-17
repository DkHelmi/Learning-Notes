---
day: 03
title: 'Menulis hipotesis: dari topik ke hipotesis yang bisa diuji, kerangka ABLE, sumber hipotesis, dan anti-pola'
researched_on: 2026-10-18
versions_checked: 'PEAK hypothesis-driven hunting (Splunk blog, 8 Mei 2023); PEAK cryptominer hunt (Splunk blog, 19 Jan 2024); Splunk .conf23 SEC1584B slides (ABLE); TaHiTI whitepaper (di-host 2026-03); MITRE ATT&CK v20.0 (13 Okt 2026), T1071.004 v1.4, T1048 v1.6, T1053.005 v1.8, DET0400; Sysmon docs (Microsoft Learn, 10 Sep 2026); Splunk CIM 6.4 Network Resolution; Splunk Enterprise 10.6 (SPL)'
---

# Day 03: Menulis hipotesis (topik, ABLE, sumber hipotesis, dan anti-pola)

Cakupan: cara mengubah brief intel, insiden lama, atau celah deteksi menjadi hipotesis hunting yang bisa dibuktikan atau dibantah, menuliskannya dengan kerangka ABLE, memastikan Evidence-nya benar-benar ada, memilih urutan pengerjaan, dan mengenali hipotesis yang buruk.

## Ide inti

Hipotesis adalah satu-satunya bagian hunt yang tidak bisa dikerjakan mesin, dan kualitasnya menentukan semua yang terjadi sesudahnya. Hipotesis yang baik menyebut perilaku yang teramati, di mana perilaku itu kemungkinan muncul, dan data apa yang akan membuktikan atau membantahnya. Kalau tidak ada hasil data yang bisa membantahnya, itu bukan hipotesis, melainkan keyakinan. Kalau datanya tidak ada, itu bukan hunt untuk sekarang, melainkan celah data yang harus dilaporkan. Sebuah brief intel yang berisi daftar IOC dan dua kalimat tentang teknik penyerang mengandung dua pekerjaan berbeda: daftar IOC dicocokkan cepat ke data historis, sedangkan kalimat tentang teknik diubah menjadi hipotesis yang tetap berguna walaupun penyerang sudah mengganti semua domain dan IP-nya.

Polanya sudah kamu kenal dari NOC. Saat pelanggan satu kawasan mengeluh lambat, engineer yang baik tidak menulis "cek jaringan". Ia menulis dugaan yang bisa diuji satu per satu: "uplink OLT di POP Bandung kongesti antara pukul 19:00 dan 22:00", lalu menentukan data yang akan menjawabnya (utilisasi interface per lima menit dari NMS). Kalau grafiknya datar di 40%, dugaan itu gugur dan ia pindah ke dugaan berikutnya. Batas analoginya: gangguan jaringan tidak berusaha mengelabui grafik, sedangkan penyerang sengaja menyamar sebagai lalu lintas sah. Karena itu hipotesis hunting harus bisa dibuktikan salah dengan data yang ada, dan "dugaan gugur" hanya berlaku untuk data, lokasi, dan rentang yang benar-benar diperiksa.

```
  brief intel | insiden lama | hasil baseline | celah deteksi
                         |
                       TOPIK                "DNS tunneling"
                         |   riset topik: seperti apa jejaknya?
                    PERTANYAAN              "Adakah data keluar lewat DNS?"
                         |   pilih satu perilaku + lokasi + data
                     HIPOTESIS              "Ada host yang mengodekan data di subdomain
                         |                   panjang ke satu domain induk, lewat resolver"
                       ABLE  -- Evidence ada? -- tidak --> celah data, bukan hunt sekarang
                         | ya
          abstract + query Evidence --> backlog, status "siap dijalankan"

  daftar IOC (domain, IP) --> pencarian indikator oleh L1 (HMM1) --> ada hit? --> triage / IR
```

Situasi Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan, kantor pusat dan data center di Jakarta, dan POP regional di Bandung, Surabaya, dan Medan. SOC PT JAB memakai Splunk Enterprise dengan Enterprise Security (ES). Log query dari empat resolver DNS internal (`jkt-res01`, `jkt-res02`, `bdg-res01`, `sby-res01`) masuk ke index `dns` dengan retensi 30 hari. Sysmon terpasang di server Windows dan sekitar 40% workstation, totalnya sekitar 214 host, tetapi hanya 186 di antaranya yang mengirim event DNS query (Event ID 22) karena konfigurasi sisanya tidak memuat tag itu. Sejak Senin 2027-02-01 kamu memegang "Program hunt PT JAB" setiap Selasa dan Kamis, dan hunt pertama (`HUNT-2027-001`, baseline parent-child) selesai hari ini. Kamis 2027-02-04 pukul 08:40, SOC lead Dimas Prasetyo meneruskan sebuah brief dan menulis:

> "Pagi. Ini brief dari forum berbagi intel ISP regional: ada kampanye ke penyedia telekomunikasi di Asia Tenggara, katanya exfil lewat DNS tunneling dan persistence pakai scheduled task. Lampirannya 40 domain dan IP. Pertanyaanku: cukup tidak kita cari 40 IOC itu saja? Kalau tidak cukup, tolong ubah brief ini jadi hipotesis yang layak masuk backlog, jangan cuma tulis 'cari DNS tunneling'. Aku perlu tahu juga isi minimal sebuah hipotesis supaya bisa langsung dikerjakan, apakah dua teknik itu diburu sekaligus atau satu-satu dan mana yang dulu, dari mana lagi ide hunt bisa datang selain brief begini, misalnya dari insiden tahun lalu, dan contoh hipotesis yang sebaiknya tidak ditulis. Anak-anak L1 mau ikut menyumbang ide, jadi aku tidak mau mereka salah arah."

Pesan itu memuat tujuh pertanyaan:

1. Cukupkah mencari 40 IOC dari brief itu?
2. Apa beda topik, pertanyaan, dan hipotesis, dan brief ini termasuk yang mana?
3. Bagaimana mengubah "DNS tunneling" menjadi hipotesis yang bisa diuji?
4. Apa isi minimal sebuah hipotesis supaya bisa langsung dikerjakan?
5. Bagaimana memastikan data untuk menguji hipotesis itu benar-benar ada?
6. Dua teknik di brief diburu sekaligus atau terpisah, dan mana yang lebih dulu?
7. Dari mana lagi hipotesis bisa datang, dan hipotesis seperti apa yang harus dihindari?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2, pertanyaan 3 di bagian 1.3, pertanyaan 4 di bagian 1.4, pertanyaan 5 di bagian 1.5, pertanyaan 6 di bagian 1.6, dan pertanyaan 7 di bagian 1.7 dan 1.8. Bagian 2 berisi hasil kerjanya: penajaman brief, tabel ABLE `HUNT-2027-002` yang ditulis ulang, abstract dan query Evidence `HUNT-2027-003` (DNS tunneling), abstract `HUNT-2027-004` (scheduled task), perbaikan hipotesis buruk, dan jawaban untuk Dimas.

**Kapan relevan:** setiap hunt hypothesis-driven; saat menerima brief intel, laporan insiden, atau temuan baseline yang perlu diubah menjadi pekerjaan yang terfokus; saat menyusun atau menyaring backlog; dan saat interview yang meminta kamu merancang hunt dari sebuah skenario.
**Kapan bukan jawaban:** saat brief hanya berisi indikator dan tugasnya mencocokkan indikator (itu pencarian indikator, cukup dikerjakan L1); saat kamu belum tahu seperti apa normal di sebuah sumber data (mulai dengan hunt baseline, yang justru sering menghasilkan hipotesis); dan saat ada insiden aktif (pertanyaannya dijawab dalam IR, bukan dimasukkan ke backlog).

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day 01 (threat hunting, detection, hipotesis, abstract, backlog, stacking, PEAK, TaHiTI, HMM, handover) tidak diulang. Tabel ini memuat istilah baru yang dipakai Day ini; kolom kanan memakai padanan dari pekerjaan NOC dan SOC.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| IOC (indicator of compromise) | Artefak atomik yang terkait serangan: hash, IP, domain, URL | MAC atau serial satu modem bermasalah yang diblokir |
| Pencarian indikator | Mencocokkan daftar IOC ke data historis; ciri HMM1 | Mencari serial modem bermasalah di inventaris |
| TTP | Tactics, techniques, and procedures: cara penyerang bekerja | Pola gangguan khas satu seri perangkat |
| Prosedur | Cara spesifik menjalankan satu teknik (misalnya T1105 lewat `certutil`) | Satu langkah konfigurasi yang memicu gangguan |
| Topik hunting | Area yang ingin diburu, belum bisa dibuktikan ("data exfiltration") | Keluhan umum "internet lambat" |
| Hipotesis yang bisa diuji | Pernyataan yang bisa dikonfirmasi atau dibantah oleh data tertentu | "Uplink OLT Bandung kongesti pukul 19:00 sampai 22:00" |
| ABLE | Kerangka PEAK untuk isi hipotesis: Actor, Behavior, Location, Evidence | Kolom wajib tiket gangguan sebelum teknisi berangkat: gejala, lokasi, data ukur |
| Evidence | Sumber data yang akan diperiksa dan seperti apa perilaku itu terlihat di sana | Grafik utilisasi, log syslog, hasil OTDR yang akan dibaca |
| Crown jewel | Aset yang paling merugikan bila disusupi | Core router dan server billing |
| DNS tunneling | Membawa data atau perintah di dalam query dan jawaban DNS | Membawa data lewat kanal manajemen yang tidak dipantau |
| Domain induk | Domain terdaftar di bawah TLD, tempat subdomain bergantung (`avcloud.example`) | Prefix agregat tempat banyak /32 berada |
| Resolver internal | Server DNS organisasi yang meneruskan query klien ke internet | Resolver ISP yang melayani pelanggan |
| Allowlist | Daftar pengecualian yang disetujui untuk aktivitas sah yang mirip serangan | Daftar IP NMS yang boleh polling SNMP |

### 1.1 Pencarian 40 IOC: tetap dikerjakan, tetapi bukan hunt

Pertanyaan pertama Dimas paling sering muncul setiap kali brief intel datang: daftar IOC sudah ada, kenapa tidak cukup mencarinya saja?

Daftar 40 domain dan IP itu berada di lapisan bawah Pyramid of Pain (Day 01 bagian 1.4): jenis indikator yang paling murah diganti penyerang. Saat brief sampai ke forum berbagi intel, infrastruktur yang disebut sering sudah dipakai berminggu-minggu dan sebagian sudah diganti. Analogi NOC-nya: memblokir MAC satu modem nakal menyelesaikan satu kasus, tetapi mengenali pola gangguan seri modem itu menangkap semua modem sejenis yang belum pernah dilaporkan. Batasnya: indikator di lapisan atas lebih tahan, tetapi lebih mahal dirumuskan dan menghasilkan lebih banyak false positive.

Pencarian IOC tetap dikerjakan karena murah dan cepat. Di PT JAB, L1 memasukkan ke-40 indikator ke threat intelligence ES dan menjalankan pencarian retroaktif ke index `proxy`, `dns`, dan `firewall`. Kegiatan ini adalah ciri HMM1 (Day 01 bagian 1.5), dan PT JAB sudah rutin melakukannya. Ada tiga batas yang harus ditulis di hasilnya:

- **Retensi:** `proxy` dan `dns` hanya menyimpan 30 hari. Bila kampanye aktif sebelum itu, pencocokan di dua index itu tidak akan menemukannya walaupun aktivitasnya pernah ada.
- **Arti "tidak ada hit":** hanya berarti 40 indikator itu tidak muncul di data yang tersimpan. Hasil itu tidak mengatakan apa pun tentang infrastruktur baru penyerang yang sama.
- **Arti "ada hit":** satu hit bukan hasil hunt, melainkan alert yang di-triage. Bila terkonfirmasi, pekerjaannya pindah ke IR.

Hunt mengambil bagian brief yang lain: dua kalimat tentang perilaku, yaitu exfiltration lewat DNS tunneling dan persistence lewat scheduled task. TaHiTI sengaja memusatkan hunting pada tiga lapisan atas piramida, yaitu TTP, tools, dan artefak host atau jaringan [S3]. Alasannya praktis: hipotesis tentang perilaku tetap berlaku setelah penyerang mengganti semua domain dan IP-nya, dan bila terbukti, polanya bisa dijadikan detection yang menangkap kampanye berikutnya.

Jawaban untuk Dimas: tidak cukup, tetapi tetap dikerjakan. IOC dicari L1 hari ini juga sebagai pencarian indikator; perilakunya dijadikan dua hipotesis di backlog.

### 1.2 Topik, pertanyaan, hipotesis

Brief dari forum menyebut "DNS tunneling" dan "scheduled task". Keduanya belum hipotesis; keduanya topik. Membedakan tiga bentuk ini adalah keterampilan pertama yang perlu dikuasai L1 yang ingin menyumbang ide.

Tabel berikut memperlihatkan tiga bentuk yang sering tertukar. Perhatikan kolom kanan: masalah tiap bentuk menunjukkan apa yang harus ditambahkan untuk naik ke bentuk berikutnya.

| Bentuk | Contoh | Masalah |
|---|---|---|
| Topik | "Data exfiltration" | Terlalu luas; bukan sesuatu yang bisa dibuktikan [S1] |
| Pertanyaan | "Apakah ada data keluar lewat cara tidak wajar?" | Lebih baik, tetapi belum menyebut cara dan data |
| Hipotesis yang bisa diuji | "Seorang aktor mungkin mengekstraksi data finansial sensitif lewat DNS tunneling" | Bisa dikonfirmasi atau dibantah dengan data tertentu [S1] |

Hipotesis yang baik bisa dibuktikan atau dibantah [S1]. Slide workshop PEAK merumuskannya sebagai pernyataan konkret tentang apa yang "mungkin" sedang terjadi, yang bisa dikonfirmasi atau disangkal dengan kombinasi data dan teknik analisis [S4]. Slide yang sama mencatat bahwa ukuran "bisa diuji" berbeda antar organisasi [S4]. Di PT JAB, hipotesis tentang DNS bisa diuji karena log resolver tersedia; di organisasi tanpa log resolver, hipotesis yang sama tidak bisa diuji.

Hipotesis juga tidak kaku. Ia disempurnakan saat investigasi memunculkan hal baru [S1]. Di diagram PEAK untuk hunt hypothesis-driven, langkah Refine di fase Execute adalah langkah opsional yang mengembalikan hunter ke Generate Hypothesis [S4].

Contoh dari slide PEAK membantu L1 memahami kenapa sebuah kalimat gagal diuji. "APT1337 ingin mencuri data kami" dinilai tidak bisa diuji: niat tidak terlihat di log, tidak ada perilaku spesifik, dan atribusi sulit. Versi yang bisa diuji menyebut perbuatan dan caranya: "APT1337 sedang mengekstraksi data dari jaringan kami lewat DNS tunneling" [S4]. Perbaikannya selalu sama: ganti niat dengan perbuatan yang teramati, dan sebut metodenya [S4].

### 1.3 Menajamkan: dari topik ke hipotesis yang bisa diuji

Dimas meminta "jangan cuma tulis 'cari DNS tunneling'". Penajaman adalah cara memenuhinya, dan PEAK menempatkannya di fase Prepare: Select Topic, Research Topic, Generate Hypothesis, Scope Hunt, lalu Plan [S1].

Contoh resmi PEAK menajamkan "data exfiltration" dalam dua langkah [S1]:

1. Topik: "data exfiltration" (terlalu luas; mencari semua jenis exfiltration tidak mungkin).
2. Bisa diuji: "Aktor mungkin mengekstraksi data sensitif lewat DNS tunneling" (dipersempit ke satu metode).
3. Diperhalus: "Aktor mungkin mengekstraksi data finansial sensitif lewat DNS tunneling" (ditambah jenis data sehingga benar-benar bisa diburu).

Pola penajaman: dari kategori besar, pilih satu metode (behavior), lalu satu konteks (data, aset, atau lokasi). Setiap langkah memotong ruang pencarian.

Langkah Research Topic sering dilewati, padahal tanpa riset kamu tidak tahu perilaku apa yang harus terlihat di data. Untuk DNS tunneling, riset singkatnya sebagai berikut:

- **Mekanisme:** program di host korban mengodekan data ke dalam nama yang di-query, biasanya di subdomain sebuah domain yang server otoritatifnya dikuasai penyerang. Query itu diteruskan resolver internal ke internet seperti query biasa, sampai tiba di server penyerang. Jawaban DNS bisa membawa perintah atau data balik. Data besar dipecah menjadi banyak query [S15].
- **Batas ukuran:** satu label DNS maksimal 63 oktet dan satu nama maksimal 255 oktet [S16]. Karena itu tunneling yang mengirim banyak data cenderung memakai label panjang mendekati batas, banyak label, dan banyak query.
- **Tipe record:** tool tunneling mendukung TXT, A, AAAA, CNAME, dan MX [S15]; ATT&CK menyebut perintah bisa disisipkan di record seperti TXT atau A [S7].
- **Pemetaan ATT&CK:** T1071.004 (Application Layer Protocol: DNS, taktik Command and Control) menyebut penyalahgunaan DNS untuk C2 ini umum disebut DNS tunneling [S7]. T1048 (Exfiltration Over Alternative Protocol, taktik Exfiltration) mencakup pencurian data lewat protokol selain kanal C2, dan DNS disebut sebagai salah satu protokol alternatif [S8]. Bila data dikirim lewat kanal C2 DNS yang sama, pemetaannya condong ke T1041 (Exfiltration Over C2 Channel); T1048 dipakai bila DNS menjadi kanal exfil yang terpisah dari C2.
- **Jejak yang diusulkan ATT&CK:** detection strategy DET0400 untuk T1071.004 memuat analytic yang mencari volume DNS tinggi dari proses non-browser, subdomain panjang atau sering, dan query terkode dari tool scripting, dengan parameter yang bisa disetel seperti ambang panjang query dan jendela waktu [S10].
- **Pemakaian sah:** vendor keamanan juga memakai teknik mirip tunneling, misalnya untuk memeriksa file dan domain secara real-time lewat DNS [S15]. Ini sumber false positive utama.

Dengan riset itu, "DNS tunneling" bisa ditajamkan menjadi kalimat yang menyebut perilaku teramati: "ada host yang mengirim banyak query dengan subdomain panjang dan bervariasi ke satu domain induk". Kalimat itu bisa dibantah: bila tidak ada domain induk dengan pola itu di log resolver, hipotesisnya gugur untuk rentang yang diperiksa.

### 1.4 Kerangka ABLE

Pertanyaan keempat Dimas (isi minimal sebuah hipotesis) dijawab PEAK dengan ABLE: empat elemen yang menangkap bagian penting hipotesis [S1]. Slide workshop PEAK menampilkannya dengan judul "Are you ABLE to hunt?" [S4].

Tabel berikut adalah keempat elemennya. Kolom kanan menunjukkan elemen mana yang boleh kosong dan apa fungsi masing-masing.

| Elemen | Arti | Catatan |
|---|---|---|
| Actor | Aktor ancaman atau tipe aktor yang dicari | Opsional; banyak hal tidak terikat aktor tertentu [S1]. Slide menulis "not always applicable" [S4] |
| Behavior | Aktivitas spesifik, biasanya TTP | Fokus satu atau dua, bukan seluruh kill chain [S1] |
| Location | Di mana di jaringan behavior itu kemungkinan muncul | Contoh PEAK: desktop pengguna atau web server yang menghadap internet. Mempersempit cakupan dan membuat hunt lebih efisien [S1] |
| Evidence | Sumber data yang diperiksa dan seperti apa aktivitasnya di sana | Mengarahkan pengumpulan dan analisis data [S1] |

Contoh ABLE PEAK untuk hipotesis DNS tunneling data finansial menunjukkan cara mengisinya [S1]. Baca baris Evidence: isinya tidak hanya nama log, tetapi juga seperti apa perilakunya terlihat.

| Elemen | Isi |
|---|---|
| Actor | Tidak ada aktor spesifik (dapat diterima, karena data finansial menarik bagi banyak penjahat siber); aktor yang diketahui akan menambah konteks seperti domain C2 |
| Behavior | Exfiltration lewat DNS tunneling |
| Location | Departemen finance (target yang dihipotesiskan) |
| Evidence | Log DNS query, atau passive DNS bila ada; cari query yang luar biasa besar atau sering, tipe query tidak lazim, dan artefak tool DNS tunneling yang diketahui |

Dari ABLE itu PEAK menurunkan rencana hunt: kumpulkan log DNS terkait finance, cari query atau jawaban yang luar biasa besar, kenali tipe record yang normal lalu periksa yang tidak lazim, dan pelajari tool DNS tunneling beserta artefaknya [S1].

Contoh cryptominer PEAK memperlihatkan Actor memang opsional: Behavior dipetakan ke T1496 Resource Hijacking dan Actor dibiarkan kosong karena cryptomining jarang terikat aktor tertentu [S2]. Location di contoh itu "semua host" karena data demonya kecil, dengan catatan bahwa hunt nyata bisa dimulai dari kelompok tertentu seperti server DMZ [S2]. Evidence-nya dua sumber dengan dua pendekatan: log performa proses untuk pemakaian CPU, dan log DNS untuk lookup ke domain cryptomining yang diketahui [S2].

Catatan ini memakai judul slide itu sebagai cek kesiapan: hipotesis siap masuk backlog dengan status "siap dijalankan" bila Behavior, Location, dan Evidence terisi, dan Evidence-nya terbukti tersedia lewat satu query cepat. Actor diisi bila ada.

### 1.5 Evidence harus benar-benar ada

Pertanyaan kelima Dimas paling sering dilupakan, padahal paling sering membuat hunt gagal di tengah jalan. Slide PEAK mengingatkan bahwa saat menyempurnakan hipotesis, kamu bisa saja mendapati datanya ternyata tidak ada [S4].

Karena data adalah hambatan nomor satu hunting (Day 01 bagian 1.7), uji setiap hipotesis dengan pertanyaan: "Apakah Evidence-nya benar-benar ada di lingkungan ini, untuk lokasi yang disebut, sepanjang rentang yang dibutuhkan?" Pertanyaan itu punya tiga bagian:

- **Ada sumbernya:** index dan sourcetype-nya ada, dan event masuk setiap hari.
- **Ada field-nya:** field yang dibutuhkan (nama query, IP klien, tipe record) terekstrak dan tidak kosong.
- **Ada cakupannya:** sumber itu mencakup Location yang disebut di ABLE, untuk rentang waktu yang direncanakan.

Untuk hipotesis DNS di PT JAB, dua sumber saling melengkapi, dan perbedaannya menentukan apa yang bisa disimpulkan:

| Sumber | Yang terlihat | Yang tidak terlihat |
|---|---|---|
| Log resolver internal (`index=dns`) | Semua klien yang memakai resolver internal, termasuk workstation tanpa Sysmon dan server Linux; IP klien, nama query, tipe record | Proses yang membuat query; host untuk IP DHCP tanpa pemetaan lease; query yang langsung ke DNS eksternal; DNS over HTTPS |
| Sysmon EID 22 (`index=sysmon`) | Host, proses (`Image`), nama query (`QueryName`), status dan hasil query [S12][S13] | Host tanpa Sysmon (sekitar 60% workstation, server Linux) dan 28 host ber-Sysmon yang konfigurasinya tanpa DnsQuery |

Sysmon EID 22 dicatat saat sebuah proses menjalankan query DNS, baik berhasil maupun gagal, dari cache maupun tidak; telemetri ini tersedia sejak Windows 8.1 [S12]. Field-nya mencakup `ProcessGuid`, `ProcessId`, `QueryName`, `QueryStatus`, `QueryResults`, `Image`, dan `User` [S13]. EID 22 berasal dari pencatatan DNS client Windows, sehingga program yang membangun paket DNS sendiri mungkin tidak tercatat; perilaku ini perlu dicek di lab sebelum dijadikan asumsi.

Satu hal teknis menguntungkan hunt ini: tunneling memakai subdomain yang hampir selalu berbeda, sehingga cache DNS client tidak menyembunyikannya. Setiap nama baru harus diteruskan ke resolver, dan karena itu terlihat di log resolver.

Bila Evidence tidak ada, hipotesisnya tidak dibuang. Ia dicatat sebagai celah visibilitas dengan pemiliknya, lalu kamu memilih hipotesis lain. Ini mencegah hunt gagal di tengah jalan karena datanya tidak pernah ada. Pemeriksaan kesiapan data yang lengkap untuk semua hunt yang sudah dibuat dibahas di Day 04.

### 1.6 Fokus satu atau dua behavior, dan memilih urutan

Brief menyebut dua perilaku. Dimas bertanya apakah keduanya diburu sekaligus.

PEAK menyarankan tidak memburu seluruh kill chain sekaligus [S1]. Satu hunt menargetkan satu atau dua behavior. Alasannya:

- Cakupan tetap bisa diselesaikan dalam waktu terencana.
- Setiap behavior dipetakan ke indikator spesifik, sehingga query dan kriteria sukses jelas.
- Kill chain penuh lebih baik dipecah menjadi beberapa hunt yang saling menyambung di backlog.

Ini juga sejalan dengan prinsip cakupan per prosedur: satu teknik ATT&CK bisa dijalankan lewat banyak prosedur berbeda (misalnya T1105 lewat certutil, bitsadmin, atau PowerShell), dan masing-masing meninggalkan jejak berbeda di log. Hunt yang menyebut prosedur mana yang diburu bisa menyatakan dengan jujur apa yang sudah dan belum diperiksa. Satu hunt yang tajam lebih bernilai daripada satu hunt yang mencoba semuanya dan tidak menyimpulkan apa pun.

DNS tunneling dan scheduled task punya data, lokasi, dan false positive yang sama sekali berbeda, jadi keduanya menjadi dua hunt: `HUNT-2027-003` dan `HUNT-2027-004`. Pertanyaan berikutnya adalah urutan. Tabel berikut menilai keduanya dengan kriteria yang bisa dipakai ulang untuk backlog mana pun; baca baris "Data hilang bila ditunda", karena di situlah keputusannya.

| Kriteria | `HUNT-2027-003` DNS tunneling | `HUNT-2027-004` scheduled task |
|---|---|---|
| Relevansi intel | Disebut brief | Disebut brief |
| Dampak bila terbukti | Data pelanggan atau internal keluar | Penyerang bertahan di host |
| Evidence terkonfirmasi hari ini | Ya (bagian 2.4 dan 2.5) | Belum; audit 4698 perlu dicek |
| Data hilang bila ditunda | Ya, `dns` hanya 30 hari | Tidak mendesak; `wineventlog` dan `sysmon` lebih panjang |
| Celah deteksi | Belum ada rule DNS tunneling | Belum ada rule untuk pembuat task tidak lazim |

Keputusannya: `HUNT-2027-003` dikerjakan lebih dulu karena datanya menyusut setiap hari dan Evidence-nya sudah terbukti. `HUNT-2027-004` ditulis lengkap hari ini sebagai abstract, lalu dijalankan setelah kesiapan datanya dicek.

### 1.7 Sumber hipotesis

Dimas ingin L1 ikut menyumbang ide. Mereka perlu tahu bahwa brief intel hanya satu dari banyak pemicu.

PEAK dan TaHiTI menyebut sumber yang saling melengkapi [S1][S3]. Slide PEAK menambahkan tren industri, kejadian terkini, kekhawatiran CISO, dan celah deteksi yang sudah diketahui sebagai masukan pemilihan topik [S4]. Tabel berikut memetakan setiap sumber ke contoh nyata di PT JAB; kolom tengah adalah bagian yang bisa langsung kamu tunjukkan ke L1.

| Sumber | Contoh di PT JAB | Catatan |
|---|---|---|
| Threat intelligence | Brief forum intel ISP regional: DNS tunneling dan scheduled task | Tim CTI, vendor intel, atau laporan publik; ambil behavior-nya, bukan hanya IOC |
| ATT&CK | DET0400 untuk T1071.004 memberi ide Evidence: proses non-browser yang banyak query DNS [S10] | Halaman group mendaftar teknik yang pernah dipakai aktor; halaman teknik menjelaskan behavior dan data yang dibutuhkan [S6] |
| Baseline / kesadaran situasi | Backlog dari `HUNT-2027-001`: eksekusi WMI dari host selain `JKT-JUMP01`; long tail dengan path dinormalisasi | Baseline sering melahirkan hipotesis |
| Keahlian domain dan pengalaman | Pengalaman NOC: resolver ISP sering jadi jalur keluar yang tidak dipantau | Intuisi yang didukung riset, bukan tebakan [S1] |
| Insiden historis | `INC-2026-026`: laptop Bandung beacon tiap lima menit ke domain baru selama akhir pekan tanpa alert | TaHiTI menyebut insiden historis sebagai pemicu [S3] |
| Red team dan crown jewel | Server billing dan RADIUS di data center; tanpa Sysmon, sehingga log resolver adalah satu-satunya Evidence DNS-nya | TaHiTI: crown jewel analysis [S3] |
| Celah use case monitoring | Belum ada rule untuk task yang dibuat parent atau user tidak lazim | Teknik relevan yang datanya ada tetapi belum punya rule (celah deteksi) |

Insiden 2026 layak dibaca ulang sebagai sumber hipotesis, dengan cara yang sama untuk setiap laporan: cari kalimat "baru ketahuan setelah" atau "tidak ada alert", lalu ubah perilakunya menjadi hipotesis.

- **`INC-2026-026`:** beacon berkala ke domain baru tanpa alert. Hipotesis turunan: "ada workstation yang menghubungi domain yang pertama kali terlihat kurang dari tujuh hari dengan interval teratur". Kandidat ini masuk backlog sebagai hunt beacon dari data proxy (Day 05).
- **`INC-2026-017`:** alert tamper antivirus P3 di `JKT-WS-0457` muncul 39 menit sebelum enkripsi dan tidak dieskalasi; akses awalnya lewat server lama tanpa EDR. Hipotesis turunan: "ada alert berprioritas rendah tentang perubahan perlindungan endpoint yang ditutup tanpa eskalasi dan berkumpul di host yang sama dalam 90 hari terakhir". Hunt seperti ini memakai data alert itu sendiri sebagai Evidence.
- **`INC-2026-019`:** host ketiga `JKT-WS-0412` baru ditemukan belakangan. Laporan seperti ini adalah tanda ada pola yang belum diburu; tulis pertanyaannya sebagai topik dulu, lalu tajamkan setelah membaca laporan insidennya.

Untuk bacaan metodologi lebih lanjut, makalah SANS 2016 karya Robert M. Lee dan David Bianco membahas tiga jenis hipotesis hunting dan kapan masing-masing dirumuskan [S18]. Cek nama ketiga jenisnya di makalah itu bila ingin memakai taksonominya di laporan.

Setiap hipotesis juga perlu batas. PEAK menyarankan menetapkan batas maksimum durasi hunt. Contoh: berburu tiga hari, dan bila tidak ada yang mencurigakan, simpulkan aktivitas itu kemungkinan tidak terjadi [S1]. Contoh cryptominer PEAK menyebut hunt biasanya mencakup setidaknya 30 hari data, walaupun dataset demonya hanya sehari [S2]. Di PT JAB, angka 30 hari itu bertabrakan dengan retensi `dns`: rentang maksimal yang bisa diperiksa adalah sekitar 30 hari ke belakang dari hari query dijalankan, dan setiap hari penundaan memotong satu hari dari awal rentang.

### 1.8 Anti-pola hipotesis

Bagian terakhir pesan Dimas ("supaya L1 tidak salah arah") dijawab dengan daftar bentuk hipotesis yang harus dihindari. Tabel berikut memuat enam anti-pola; kolom kanan adalah perbaikan yang bisa langsung diterapkan.

| Anti-pola | Contoh | Perbaikan |
|---|---|---|
| Terlalu luas | "Cari aktivitas berbahaya" | Pilih satu behavior dan satu lokasi |
| Tidak bisa dibantah | "Pasti ada penyerang di jaringan" | Rumuskan behavior spesifik yang hasil datanya bisa menyangkal |
| Hanya indikator (IOC) | "Cari 50 IP dari laporan" | Naik ke TTP: behavior aktor, bukan alamatnya (Day 01 bagian 1.4, Pyramid of Pain) |
| Tanpa Evidence | "Aktor memakai teknik X" tanpa tahu log apa | Isi Evidence dulu; bila data tidak ada, itu hunt gagal karena data |
| Menebak tanpa Knowledge | Hipotesis tanpa dasar intel atau pengalaman | Sandarkan pada salah satu sumber di bagian 1.7 |
| Seluruh kill chain | "Lacak intrusi dari phishing sampai exfiltration" | Pecah menjadi beberapa hunt di backlog |

Ada satu anti-pola lagi yang muncul dari slide PEAK: hipotesis tentang niat ("aktor ingin mencuri data") [S4]. Niat tidak terlihat di log. Gantilah dengan perbuatan yang teramati, seperti dijelaskan di bagian 1.2.

## 2. Contoh dan langkah praktis: dari brief ke backlog PT JAB

Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi. Query ditulis untuk Splunk PT JAB (`jkt-splunk-sh01`, role `jab_hunter`); untuk latihan, jalankan versi yang disesuaikan di lab pribadi (bagian 3).

### 2.1 Penajaman brief menjadi hipotesis

Tabel ini adalah langkah pertama yang kamu kerjakan setelah membaca pesan Dimas: setiap bagian brief, plus satu hunt yang sudah berjalan, dipetakan dari pemicu ke topik lalu ke hipotesis yang bisa diuji. Baca kolom kanan; setiap kalimat di sana bisa dibantah oleh data tertentu.

| Trigger | Topik | Hipotesis yang bisa diuji |
|---|---|---|
| Brief: 40 domain dan IP | (bukan topik hunt) | Pencarian indikator oleh L1 di `proxy`, `dns`, `firewall`, 30 hari terakhir |
| Brief: exfil lewat DNS tunneling | Anomali DNS | "Ada host PT JAB yang mengirim banyak query dengan subdomain panjang dan bervariasi ke satu domain induk lewat resolver internal, tanpa memicu alert" (`HUNT-2027-003`) |
| Brief: persistence lewat scheduled task | Scheduled task | "Ada scheduled task yang dibuat di host Windows PT JAB oleh parent process atau user yang tidak lazim untuk membuat task, tanpa memicu alert" (`HUNT-2027-004`) |
| Intel publik: aktor memakai LOLBin untuk mengunduh tahap kedua | Ingress tool transfer | "LOLBin (certutil, bitsadmin, mshta) di endpoint ber-Sysmon mengunduh file dari URL eksternal tanpa memicu alert" (`HUNT-2027-002`, Day 02) |

Perhatikan baris pertama: daftar IOC tidak punya topik hunt, karena pertanyaannya sudah terjawab oleh pencocokan. Menuliskannya di tabel tetap berguna supaya Dimas melihat bahwa IOC tidak diabaikan.

**Kapan gagal:** hipotesis ditulis dengan istilah brief apa adanya ("ada aktivitas kampanye X"). Istilah brief adalah topik; tanpa riset topik (bagian 1.3), kamu tidak tahu perilaku apa yang harus terlihat di data.

### 2.2 `HUNT-2027-002` ditulis ulang sebagai tabel ABLE

Hunt LOLBin `HUNT-2027-002` dibuat dari laporan intel publik dan sudah dijalankan di Day 02 dengan hasil tidak terbukti (aktivitas yang ditemukan jinak). Menulis ulang abstract-nya sebagai ABLE adalah latihan yang baik, karena ABLE memperlihatkan hal yang tidak terlihat di abstract biasa.

| Elemen | Isi |
|---|---|
| Actor | Tidak spesifik (LOLBin dipakai banyak aktor); laporan intel publik yang menjadi pemicu tidak menyebut aktor yang relevan untuk PT JAB. Bila intel menyebut aktor, tambahkan domain atau URL yang diketahui |
| Behavior | T1105 Ingress Tool Transfer lewat LOLBin (certutil, mshta, bitsadmin) |
| Location | Endpoint Windows ber-Sysmon di PT JAB (server Windows dan workstation OU `Workstations-EDR`) |
| Evidence | Sysmon EID 1 (command line LOLBin dengan argumen unduh atau URL) dan EID 3 (koneksi keluar), 18 Januari sampai 1 Februari 2027; cari argumen URL http/https dan koneksi ke IP eksternal |

Cek kesiapan: Behavior, Location, dan Evidence terisi, dan Evidence tersedia. Kriteria sukses: semua eksekusi LOLBin dengan argumen unduh ditinjau dan diberi label. Hasil dan rinciannya ada di Day 02.

**Cara membaca:** baris Location dan Evidence tidak sepenuhnya cocok. EID 1 datang dari 214 host, tetapi EID 3 hanya dari 198 host. Untuk 16 host sisanya, bagian "koneksi keluar" dari hipotesis tidak bisa diuji. ABLE membuat ketidakcocokan seperti ini terlihat sebelum laporan ditulis, sehingga laporan bisa menyebutnya sebagai cakupan yang berkurang, bukan baru ketahuan saat ditanya.

**Kapan gagal:** ABLE diisi setelah hasil keluar untuk merapikan dokumentasi. ABLE yang ditulis belakangan cenderung menyesuaikan Location dengan data yang kebetulan ada, sehingga celah cakupan tidak pernah tercatat.

### 2.3 Abstract dan ABLE `HUNT-2027-003`

Abstract ini adalah jawaban utama untuk permintaan Dimas "ubah brief jadi hipotesis yang layak masuk backlog". Formatnya sama dengan abstract `HUNT-2027-001` (Day 01 bagian 2.1), ditambah baris ABLE dan status.

```
ID             : HUNT-2027-003
Dibuat         : 2027-02-04 (Kamis), pemilik: <kamu>, reviewer: Dimas Prasetyo
Trigger        : Intel - brief forum berbagi intel ISP regional (diterima 2027-02-04): kampanye terhadap
                 penyedia telekomunikasi Asia Tenggara, exfiltration lewat DNS tunneling
Tipe (PEAK)    : Hypothesis-driven
Hipotesis      : Ada host PT JAB yang mengirim data keluar dengan mengodekannya di subdomain panjang dan
                 bervariasi ke satu domain induk, lewat resolver internal, tanpa memicu alert.
ATT&CK         : T1071.004 Application Layer Protocol: DNS (Command and Control);
                 T1048 Exfiltration Over Alternative Protocol (Exfiltration) bila DNS kanal exfil terpisah
Data           : index=dns (jkt-res01, jkt-res02, bdg-res01, sby-res01), 28 hari:
                 Kamis 2027-01-07 00:00 sampai Kamis 2027-02-04 00:00 WIB;
                 Sysmon EID 22 (186 host) untuk atribusi proses; index=firewall untuk DNS keluar langsung
Teknik analisis: Stacking per domain induk: subdomain unik, panjang subdomain, tipe record, jumlah klien
Di luar cakupan: DNS over HTTPS; trafik DNS pelanggan broadband; exfil sangat lambat
                 (kurang dari 50 subdomain unik per domain induk dalam 28 hari, lihat bagian 2.6)
Kriteria sukses: Semua domain induk yang lolos ambang ditinjau dan diberi label
                 jinak / perlu investigasi / data tidak cukup
Batas waktu    : 3 hari hunting
Hasil mungkin  : ditemukan | tidak ditemukan | inkonklusif | data tidak cukup
Handover       : IR (Dimas) bila ditemukan; Sari Kusuma untuk usulan detection;
                 Agung Prabowo untuk celah data (EID 22 di 28 host, pemetaan IP ke host)
Status         : Siap dijalankan (Evidence terkonfirmasi 2027-02-04, agregat 28 hari disimpan)
```

Tabel ABLE-nya merangkum empat elemen yang sama dalam bentuk yang bisa dibaca L1 dalam setengah menit.

| Elemen | Isi |
|---|---|
| Actor | Kampanye di brief forum; aktor tidak dinamai. Bila nanti ada nama, tambahkan domain induk dan tool yang dikaitkan |
| Behavior | Data dikodekan di subdomain panjang (mendekati batas 63 karakter per label) ke satu domain induk, banyak subdomain unik, kadang tipe record TXT; T1071.004 dan T1048 |
| Location | Semua klien resolver internal. Prioritas: segmen data center `10.20.0.0/16` (server billing dan RADIUS, tanpa Sysmon) dan workstation Jakarta `10.10.0.0/16` |
| Evidence | Log resolver di `index=dns` (field `src`, `query`, `record_type`): banyak subdomain unik dan panjang per domain induk. Sysmon EID 22 (`Image`, `QueryName`) untuk mengetahui proses di 186 host. `index=firewall` untuk query port 53 yang keluar langsung tanpa resolver |

Cara membaca elemennya:

- **Behavior** ditulis sebagai sesuatu yang terlihat di log (panjang, jumlah unik, tipe record), bukan sebagai nama teknik saja. Itu yang membuat hipotesis bisa dibantah.
- **Location** menyebut prioritas, bukan hanya "semua host". Server billing dan RADIUS adalah crown jewel ISP, dan karena tidak ber-Sysmon, log resolver adalah satu-satunya Evidence DNS-nya.
- **Di luar cakupan** menulis DNS over HTTPS dengan jujur. Program yang memakai DoH tidak melewati resolver internal, jadi tidak terlihat di hunt ini.

**Kapan gagal:** rentang 28 hari ditulis, tetapi hunt baru dijalankan dua minggu kemudian. Dengan retensi 30 hari, separuh rentang sudah hilang. Bagian 2.6 menunjukkan cara mengamankan agregatnya hari ini.

### 2.4 Query Evidence 1: log resolver tersedia dan sepanjang apa

Query ini menjawab bagian pertama cek Evidence (bagian 1.5): apakah keempat resolver mengirim log, dan sejak kapan data tersedia.

**Tujuan:** memastikan `index=dns` berisi data dari keempat resolver dan mengetahui event tertua yang masih tersimpan.

**Asumsi data:** log query resolver masuk ke `index=dns` dengan `host` berisi nama resolver. Cek nama index dan sourcetype di lingkunganmu.

```
| tstats count AS events min(_time) AS first_event max(_time) AS last_event
    WHERE index=dns earliest=0 BY host
| eval first_event=strftime(first_event, "%Y-%m-%d %H:%M"),
       last_event=strftime(last_event, "%Y-%m-%d %H:%M")
| sort host
```

Tabel berikut menjelaskan tiap bagian query.

| Bagian | Fungsi |
|---|---|
| `tstats ... WHERE index=dns` | Membaca indexed field saja, sehingga cepat walaupun datanya ratusan juta event |
| `earliest=0` | Semua data yang masih tersimpan; di sini sengaja tidak memakai rentang, karena yang dicari justru batas retensi |
| `min(_time)` / `max(_time)` | Event tertua dan terbaru per resolver |
| `BY host` | Satu baris per resolver; resolver yang tidak muncul berarti tidak mengirim log |
| `strftime(...)` | Mengubah epoch menjadi tanggal yang bisa dibaca |

Keluaran ilustrasi (dijalankan Kamis 2027-02-04 08:58):

```
host       events        first_event       last_event
bdg-res01   58.231.904   2027-01-05 02:16  2027-02-04 08:57
jkt-res01  183.412.660   2027-01-05 02:14  2027-02-04 08:57
jkt-res02  176.090.115   2027-01-05 02:14  2027-02-04 08:57
sby-res01   20.744.318   2027-01-05 02:15  2027-02-04 08:57
```

**Cara membaca hasil:** keempat resolver mengirim log sampai menit terakhir, jadi sumbernya hidup. Event tertua tanggal 5 Januari, sesuai retensi 30 hari. Rentang abstract (mulai 7 Januari) masih utuh hari ini, tetapi mulai terpotong sekitar Sabtu 2027-02-06. Splunk menghapus data per bucket, jadi data tertua bisa bertahan sedikit lebih lama dari 30 hari; jangan mengandalkannya.

**Variasi:** cek kelengkapan field untuk satu hari: `index=dns earliest="02/03/2027:00:00:00" latest="02/04/2027:00:00:00" | stats count AS events count(query) AS has_query count(src) AS has_src count(record_type) AS has_rtype BY host`. Bila `has_query` atau `has_rtype` jauh di bawah `events`, field extraction resolver itu bermasalah dan hunt untuk resolver tersebut menjadi data tidak cukup. Nama field `query`, `src`, dan `record_type` mengikuti data model CIM Network Resolution [S17]; cek apakah add-on resolver-mu memetakannya.

**Kapan gagal:** satu resolver memakai software berbeda dan lognya masuk ke index lain; resolver cadangan yang hanya aktif saat failover tidak pernah dikonfigurasi forwarder-nya; atau `earliest=0` dijalankan pada index yang sangat besar tanpa `tstats` sehingga search terlalu lama.

### 2.5 Query Evidence 2: cakupan Sysmon EID 22

Query ini menjawab bagian "cakupan" dari cek Evidence untuk sumber kedua. Log resolver memberi IP klien; untuk mengetahui proses mana yang membuat query, kamu butuh Sysmon EID 22, dan cakupannya harus diukur, bukan diasumsikan.

**Tujuan:** menghitung berapa host ber-Sysmon yang mengirim EID 22, dibanding host yang mengirim EID 1, selama tujuh hari.

```
index=sysmon sourcetype=XmlWinEventLog (EventCode=1 OR EventCode=22)
    earliest="01/28/2027:00:00:00" latest="02/04/2027:00:00:00"
| stats count(eval(EventCode=1)) AS eid1 count(eval(EventCode=22)) AS eid22 BY host
| stats count AS hosts_total
        count(eval(eid22>0)) AS hosts_with_eid22
        count(eval(eid22=0)) AS hosts_without_eid22
```

| Bagian | Fungsi |
|---|---|
| `(EventCode=1 OR EventCode=22)` | EID 1 sebagai pembanding: host yang aktif mengirim Sysmon pasti punya process creation |
| `earliest=... latest=...` | Tujuh hari absolut, cukup untuk menutup host yang jarang menyala |
| `count(eval(EventCode=22))` | Menghitung hanya event yang memenuhi kondisi; idiom umum untuk menghitung bersyarat di `stats` |
| `stats ... BY host` lalu `stats` kedua | Pertama per host, lalu diringkas menjadi tiga angka |

Keluaran ilustrasi:

```
hosts_total  hosts_with_eid22  hosts_without_eid22
214          186               28
```

**Cara membaca hasil:** 186 dari 214 host ber-Sysmon mengirim EID 22. Selisih 28 host adalah host dengan konfigurasi Sysmon tanpa tag DnsQuery. Ini celah data yang jelas pemiliknya (tim Infrastruktur, Agung Prabowo), bukan alasan menunda hunt. Yang lebih penting: Sysmon hanya ada di sekitar 40% workstation. Jadi EID 22 dipakai untuk atribusi proses pada kandidat yang muncul, sedangkan cakupan utama hunt tetap log resolver.

**Variasi:** ganti `stats` kedua dengan `where eid22=0 | table host eid1` untuk mendapatkan daftar 28 host itu, lalu lampirkan ke tiket untuk tim Infrastruktur. Untuk melihat proses apa saja yang biasanya membuat query di host ber-EID 22, jalankan `index=sysmon EventCode=22 earliest=... latest=... | stats dc(host) AS hosts count BY Image | sort - hosts`; daftar ini menjadi baseline kasar proses yang normal melakukan DNS.

**Kapan gagal:** nama field `EventCode` berbeda setelah parsing add-on (misalnya `EventID`); `host` di Splunk berisi FQDN untuk sebagian host dan nama pendek untuk yang lain, sehingga satu host terhitung dua kali; atau host yang mati selama tujuh hari tidak terlihat sama sekali dan tidak masuk hitungan mana pun.

### 2.6 Query analisis `HUNT-2027-003`: stacking per domain induk

Query ini adalah inti hunt yang statusnya "siap dijalankan". Hari ini query dijalankan pada sampel satu hari untuk menguji bahwa logikanya bekerja dan untuk melihat false positive pertama, lalu agregat 28 hari disimpan sebelum datanya mulai hilang.

**Tujuan:** menemukan domain induk yang menerima banyak subdomain unik yang panjang, karena itulah jejak data yang dikodekan di nama query.

**Asumsi data:** field `query`, `src`, dan `record_type` terekstrak (bagian 2.4). Domain eksternal di contoh ini memakai TLD satu label (`.example`, `.test`).

```
index=dns earliest="02/03/2027:00:00:00" latest="02/04/2027:00:00:00"
| eval q=lower(rtrim(query, "."))
| rex field=q "^(?<sub>.+)\.(?<parent>[^.]+\.[^.]+)$"
| eval sub_len=len(sub)
| stats count AS queries dc(sub) AS unique_sub avg(sub_len) AS avg_sub_len max(sub_len) AS max_sub_len
        dc(src) AS clients values(record_type) AS rtypes BY parent
| where unique_sub > 200 AND avg_sub_len > 30
| eval avg_sub_len=round(avg_sub_len, 1)
| sort - unique_sub
```

Tabel berikut menjelaskan tiap baris query.

| Baris | Fungsi |
|---|---|
| `earliest="02/03/2027:00:00:00" latest="02/04/2027:00:00:00"` | Sampel satu hari (Rabu 3 Februari) untuk uji logika; hunt penuh memakai 28 hari |
| `lower(rtrim(query, "."))` | Menyamakan huruf dan membuang titik di ujung nama, supaya `A.example.` dan `a.example` terhitung sama |
| `rex ... "^(?<sub>.+)\.(?<parent>[^.]+\.[^.]+)$"` | Memisahkan dua label terakhir sebagai domain induk dan sisanya sebagai subdomain |
| `len(sub)` | Panjang bagian subdomain, tempat data dikodekan |
| `dc(sub)` | Jumlah subdomain unik per domain induk; tunneling menghasilkan nama yang hampir selalu baru |
| `dc(src)` / `values(record_type)` | Berapa klien yang terlibat, dan tipe record apa yang dipakai |
| `where unique_sub > 200 AND avg_sub_len > 30` | Ambang awal (asumsi), disetel dari baseline di Day 05 |
| `round(...)` lalu `sort` | Merapikan angka, lalu domain dengan subdomain unik terbanyak di atas |

Nama tanpa subdomain (misalnya `avcloud.example` saja) tidak cocok dengan regex, sehingga `parent` kosong dan baris itu tidak ikut dihitung. Itu disengaja, karena nama tanpa subdomain tidak bisa membawa data yang dikodekan.

Keluaran ilustrasi:

```
Domain induk unik pada 3 Feb 2027 : 61.402
Lolos ambang                      : 1

parent           queries  unique_sub  avg_sub_len  max_sub_len  clients  rtypes
avcloud.example  48.210   31.877      42.0         42           1        A
```

**Cara membaca hasil:** satu domain induk lolos, dengan pola yang menarik sekaligus mencurigakan: hampir 32 ribu subdomain unik dalam sehari. Tiga ciri membuatnya cepat terbaca sebagai jinak. Pertama, panjang subdomain selalu 42 karakter (rata-rata dan maksimum sama), yang cocok dengan 40 karakter heksadesimal hash SHA-1 ditambah satu label pendek (`<hash>.h`). Data yang dikodekan dari file biasanya menghasilkan panjang yang bervariasi dan mendekati batas 63 karakter per label. Kedua, hanya ada satu klien. Ketiga, tipe record-nya A biasa. Pivot ke `src` menunjukkan `10.20.3.60`, yaitu server proxy web `jkt-proxy01`. Tim Infrastruktur mengonfirmasi bahwa engine antivirus di proxy memeriksa reputasi hash setiap file unduhan lewat DNS ke vendornya, dan dokumentasi vendor menyebut domain itu. Vendor keamanan memang memakai teknik mirip tunneling untuk pemeriksaan file secara real-time [S15].

Label: jinak. Domain ini masuk allowlist hunt `jab_hunt_allowlist_dns.csv` dengan pengecualian sempit: kombinasi domain induk `avcloud.example` dan klien `10.20.3.60`, bukan domain induknya saja. Bila suatu hari host lain mengirim query ke domain yang sama, itu tetap muncul.

**Variasi:** simpan agregat 28 hari hari ini juga, supaya hunt tetap bisa dijalankan setelah data mentah lewat retensi:

```
index=dns earliest="01/07/2027:00:00:00" latest="02/04/2027:00:00:00"
| eval q=lower(rtrim(query, "."))
| rex field=q "^(?<sub>.+)\.(?<parent>[^.]+\.[^.]+)$"
| eval sub_len=len(sub)
| stats count AS queries dc(sub) AS unique_sub avg(sub_len) AS avg_sub_len max(sub_len) AS max_sub_len
        dc(src) AS clients values(record_type) AS rtypes min(_time) AS first_seen max(_time) AS last_seen
        BY parent
| where unique_sub > 50
| outputlookup jab_hunt_baseline_dns_parent.csv
```

Agregat dihitung untuk seluruh 28 hari sekaligus, bukan per hari, karena jumlah unik tidak bisa dijumlahkan antar hari: subdomain yang sama di dua hari akan terhitung dua kali. Filter `unique_sub > 50` lebih longgar daripada ambang hunt (200), sehingga ambang masih bisa diturunkan sampai 50 saat hunt dijalankan tanpa mengubah pertanyaannya. Konsekuensinya ditulis di abstract: domain induk dengan kurang dari 50 subdomain unik dalam 28 hari berada di luar cakupan. Keluaran ilustrasi: 4.318 domain induk tersimpan. Untuk kandidat dengan data mentah yang sudah hilang, pivot proses masih bisa dilakukan lewat Sysmon EID 22 bila host-nya termasuk 186 host itu.

Variasi kedua memakai Sysmon untuk atribusi proses pada kandidat: `index=sysmon EventCode=22 QueryName="*.avcloud.example" earliest=... latest=... | stats count dc(QueryName) AS unique_names BY host Image`. Analytic ATT&CK DET0400 menyoroti query DNS dalam jumlah besar dari proses non-browser seperti PowerShell, rundll32, atau python [S10]; `Image` yang tidak lazim untuk DNS adalah sinyal kedua yang menguatkan kandidat.

**Kapan gagal:** domain induk memakai TLD dua label seperti `co.id`, sehingga regex memotong di tempat yang salah dan semua domain `*.co.id` tergabung menjadi satu; tunneling sangat lambat yang tidak pernah melewati ambang; penyerang memakai banyak domain induk sekaligus sehingga tiap domain di bawah ambang; atau program memakai DNS over HTTPS sehingga query tidak pernah sampai ke resolver internal.

### 2.7 Abstract dan ABLE `HUNT-2027-004`

Abstract ini mengubah bagian kedua brief (persistence lewat scheduled task) menjadi hipotesis. Hari ini hanya abstract dan ABLE yang ditulis; hunt ini dijalankan di Day 07 setelah kesiapan datanya dicek di Day 04.

Riset topiknya singkat. T1053.005 (Scheduled Task/Job: Scheduled Task) di ATT&CK v20.0 tercatat di tiga taktik: Execution, Persistence, dan Privilege Escalation [S9]. Task bisa dibuat lewat `schtasks`, GUI, wrapper .NET, library netapi32, WMI, atau cmdlet PowerShell `Invoke-CimMethod` [S9]. ATT&CK juga mencatat task tersembunyi yang tidak terlihat oleh `schtasks /query` dan UI Task Scheduler, misalnya dengan menghapus nilai Security Descriptor task di registry, yang membutuhkan hak SYSTEM [S9]. Detection strategy DET0441 untuk teknik ini mencari pembuatan atau perubahan task lewat Task Scheduler, WMI, PowerShell, atau API yang diikuti eksekusi dari `svchost.exe` atau `taskeng.exe` [S9].

Karena jalur pembuatannya banyak, Evidence-nya juga lebih dari satu. Event Security 4698 ("A scheduled task was created") ditulis setiap kali task baru dibuat, dari subcategory Audit Other Object Access Events [S14]. Event itu memuat akun pembuat (`SubjectUserName`), nama task (`TaskName`), isi XML task (`TaskContent`), dan sejak Windows 10 1903 juga `ClientProcessId` dan `ParentProcessId` [S14]. Microsoft menyarankan memantau task baru di root Task Scheduler Library (nama seperti `\NAMA_TASK`), karena task yang dibuat manual atau oleh malware sering berada di sana [S14].

```
ID             : HUNT-2027-004
Dibuat         : 2027-02-04 (Kamis), pemilik: <kamu>, reviewer: Dimas Prasetyo
Trigger        : Intel - brief forum berbagi intel ISP regional (2027-02-04): persistence lewat scheduled task;
                 celah deteksi - belum ada rule untuk task yang dibuat parent/user tidak lazim
Tipe (PEAK)    : Hypothesis-driven, dengan stacking pembuat task
Hipotesis      : Ada scheduled task yang dibuat di host Windows PT JAB oleh parent process atau user
                 yang tidak lazim untuk membuat task, tanpa memicu alert.
ATT&CK         : T1053.005 Scheduled Task/Job: Scheduled Task (Execution, Persistence, Privilege Escalation)
Data           : Security 4698 di index=wineventlog; Sysmon EID 1 (schtasks.exe dan powershell.exe beserta
                 ParentImage, User) di index=sysmon; rentang 28 hari, tanggal absolut ditetapkan saat eksekusi
Di luar cakupan: Host tanpa audit 4698 dan tanpa Sysmon (jumlahnya ditulis di laporan); task tersembunyi
                 yang dibuat dengan manipulasi registry langsung
Kriteria sukses: Semua kombinasi pembuat (akun + parent process) yang langka ditinjau dan diberi label;
                 setiap task di root Task Scheduler Library ditinjau
Hasil mungkin  : ditemukan | tidak ditemukan | inkonklusif | data tidak cukup
Handover       : IR (Dimas) bila ditemukan; Sari Kusuma untuk usulan detection;
                 Agung Prabowo bila audit 4698 belum aktif merata
Status         : Menunggu kesiapan data (Day 04); dijalankan di Day 07
```

| Elemen | Isi |
|---|---|
| Actor | Kampanye di brief forum; aktor tidak dinamai |
| Behavior | Pembuatan scheduled task oleh parent process atau user yang jarang membuat task (misalnya Office, browser, script host, atau akun pengguna biasa di server); T1053.005 |
| Location | Server Windows dan workstation ber-Sysmon (OU `Workstations-EDR`); prioritas server di data center |
| Evidence | 4698: `SubjectUserName`, `TaskName`, `TaskContent` (perintah dan akun yang menjalankan), `ClientProcessId` untuk korelasi ke Sysmon EID 1. Sysmon EID 1: `schtasks.exe` dengan `/create`, `ParentImage`, `User`. Status audit 4698 di PT JAB belum dicek |

**Cara membaca:** baris Evidence menulis "belum dicek" dengan terang. Cek kesiapan (bagian 1.4) belum lulus, sehingga status abstract ini "menunggu kesiapan data", bukan "siap dijalankan". Itu bukan kelemahan abstract; justru itu yang mencegah hunt dijalankan di atas data yang ternyata kosong. Hunt yang hanya membaca `schtasks.exe` di Sysmon punya blind spot untuk task yang dibuat lewat API atau WMI; 4698 menutup blind spot itu karena ditulis apa pun jalur pembuatannya, selama audit-nya aktif.

**Kapan gagal:** Location ditulis "semua host Windows" padahal 4698 belum tentu diaudit di semua host; atau Behavior ditulis "scheduled task mencurigakan" tanpa menyebut apa yang membuatnya mencurigakan, sehingga kriteria sukses tidak bisa dirumuskan.

### 2.8 Hipotesis buruk diperbaiki

Tabel ini adalah bahan untuk L1 yang ingin menyumbang ide, sesuai permintaan Dimas. Setiap baris memperlihatkan hipotesis yang sering ditulis, kenapa ia gagal, dan versi yang bisa diuji di PT JAB.

| Buruk | Kenapa | Diperbaiki |
|---|---|---|
| "Cari ransomware di jaringan PT JAB" | Topik, bukan hipotesis; tidak bisa dibantah | "Ada proses di host Windows ber-Sysmon yang menghapus shadow copy lewat vssadmin/wmic/WMI dalam 24 jam setelah eksekusi dari folder user-writable" (T1490) |
| "Cek 40 domain dan IP dari brief forum" | Hanya indikator (HMM1) | Tetap dikerjakan L1 sebagai pencarian indikator; hipotesisnya: "Ada workstation yang membuat koneksi berulang berpola beacon (interval tetap) ke satu tujuan eksternal, menandakan C2" |
| "Aktor APT ada di jaringan kita" | Tidak bisa diuji, tanpa behavior | "Ada akun yang login ke Entra ID dari lokasi tidak lazim lalu membuat akun baru di AD dalam 1 jam" |
| "Kelompok di brief ingin mencuri data pelanggan" | Niat tidak terlihat di log [S4] | "Ada host di segmen `10.20.0.0/16` yang mengirim data lewat subdomain DNS panjang ke satu domain induk" (`HUNT-2027-003`) |

Perhatikan: setiap perbaikan menyebut behavior yang konkret, lokasi, dan secara implisit Evidence, sehingga bisa ditulis sebagai ABLE.

**Kapan gagal:** versi perbaikan menyebut data yang tidak ada di PT JAB. Hipotesis baris ketiga, misalnya, butuh log sign-in Entra ID (ada di index `o365`) dan event pembuatan akun AD (4720 di `wineventlog`); bila salah satunya tidak dikumpulkan, hipotesis itu kembali ke status celah data.

### 2.9 Jawaban untuk Dimas dan isi backlog

Ringkasan berikut adalah balasan yang kamu kirim ke Dimas Kamis siang. Kolom kanan merujuk subbagian, supaya Dimas bisa membaca alasannya bila L1 atau Hendra bertanya.

| Pertanyaan Dimas | Jawaban singkat | Dasar |
|---|---|---|
| Cukup cari 40 IOC? | Tidak cukup, tetapi tetap dikerjakan L1 hari ini sebagai pencarian indikator; hasilnya terbatas retensi 30 hari | Bagian 1.1 |
| Brief ini hipotesis atau bukan? | Belum; "DNS tunneling" dan "scheduled task" adalah topik | Bagian 1.2 |
| Bagaimana menajamkannya | Riset jejaknya, lalu tulis perilaku yang teramati, lokasi, dan data | Bagian 1.3, 2.1 |
| Isi minimal hipotesis | ABLE: Behavior, Location, Evidence wajib; Actor opsional | Bagian 1.4 |
| Datanya ada? | DNS: ya, log resolver 4 resolver dan EID 22 di 186 host; scheduled task: audit 4698 belum dicek | Bagian 1.5, 2.4, 2.5 |
| Sekaligus atau terpisah, mana dulu | Terpisah: `HUNT-2027-003` dulu karena data DNS hilang setelah 30 hari; `HUNT-2027-004` setelah kesiapan data | Bagian 1.6 |
| Sumber ide lain dan yang dihindari | Insiden 2026, baseline, ATT&CK, crown jewel, celah deteksi; hindari topik, niat, dan IOC yang disebut hipotesis | Bagian 1.7, 1.8, 2.8 |

Isi `jab-hunt/backlog/BACKLOG.md` setelah hari ini:

```
HUNT-2027-001  Baseline parent-child Sysmon EID 1            selesai 2027-02-04, tidak ditemukan
HUNT-2027-002  LOLBin mengunduh tahap kedua (T1105)          selesai, tidak terbukti (Day 02)
HUNT-2027-003  DNS tunneling (T1071.004, T1048)              siap dijalankan, agregat 28 hari disimpan
HUNT-2027-004  Scheduled task oleh parent/user tidak lazim   menunggu kesiapan data, jadwal Day 07
(kandidat)     Eksekusi WMI dari host selain JKT-JUMP01      dari HUNT-2027-001
(kandidat)     Long tail parent-child dengan path dinormalisasi  dari HUNT-2027-001
(kandidat)     Beacon ke domain baru dari workstation        dari INC-2026-026
(kandidat)     Alert P3 perlindungan endpoint yang berkumpul di satu host  dari INC-2026-017
```

**Kapan gagal:** kandidat dari insiden langsung diberi nomor hunt dan target selesai sebelum dicek Evidence-nya. Nomor hunt sebaiknya diberikan setelah ABLE lengkap, supaya backlog tidak penuh dengan hunt yang tidak pernah bisa dijalankan.

## 3. Lab praktik (di VM lab terisolasi)

**Prasyarat:** `hunts/BACKLOG.md` dari Day 01-02 di repo portofolio pribadi; akses ke ATT&CK; Splunk lab dengan Sysmon (termasuk DnsQuery) dari minimal satu VM Windows dengan snapshot bersih. Jangan memakai data, nama, atau kejadian dari pekerjaan nyata; PT JAB hanya contoh fiktif.

1. **Tiga hipotesis.** Ambil tiga trigger dari backlog. Untuk masing-masing, tulis penajaman topik ke hipotesis yang bisa diuji dengan format tabel bagian 2.1, lalu tabel ABLE lengkap.
2. **Cek ABLE.** Untuk tiap hipotesis, pastikan Behavior, Location, dan Evidence terisi, dan Evidence benar-benar ada di lab: jalankan satu query cepat untuk memastikan data ada, dengan pola bagian 2.4 dan 2.5. Di lab, query Evidence DNS bisa berupa `index=sysmon EventCode=22 earliest=-30d@d | stats count dc(QueryName) AS names BY host`; karena lab-mu data live, rentang relatif boleh, tetapi tulis rentang absolutnya di catatan hasil.
3. **Uji positif DNS.** Di VM Windows lab, buat sekitar 300 query `nslookup` dengan label acak 40 sampai 60 karakter heksadesimal ke satu domain yang tidak ada di bawah `.test` (misalnya `lab-tunnel.test`). Query ini jinak: tidak ada data yang dikirim ke mana pun dan domainnya tidak bisa di-resolve. Jalankan query bagian 2.6 versi Sysmon (ganti `query` dengan `QueryName` dan `index=dns` dengan `index=sysmon EventCode=22`), lalu pastikan `lab-tunnel.test` muncul dengan `unique_sub` sekitar 300. Catat juga `Image`-nya. Kembalikan snapshot setelah selesai.
4. **Pilih behavior.** Untuk hipotesis yang menyentuh lebih dari dua behavior, pecah menjadi beberapa hipotesis di backlog. Tandai mana yang dikerjakan lebih dulu memakai kriteria tabel bagian 1.6.
5. **Kriteria sukses dan waktu.** Tambahkan kriteria sukses dan batas durasi ke tiap hipotesis. Bila salah satu sumber datanya punya retensi pendek, tulis tanggal terakhir hunt itu masih bisa dijalankan dengan rentang penuh.
6. **Perbaiki yang buruk.** Tulis tiga hipotesis buruk (dari kebiasaan lama atau contoh bagian 2.8), lalu perbaiki masing-masing. Jelaskan apa yang berubah.
7. **Perbarui backlog.** Ganti trigger mentah di backlog dengan hipotesis ABLE yang sudah ditajamkan; beri status "siap dijalankan" hanya pada yang Evidence-nya sudah terbukti.

**Hasil yang sebaiknya tersimpan:**

- Tiga hipotesis bisa diuji, masing-masing dengan tabel ABLE.
- Evidence tiap hipotesis dikonfirmasi ada di lab (atau ditandai celah visibilitas).
- Bukti uji positif DNS: jumlah subdomain unik, panjang rata-rata, dan `Image` yang membuat query.
- Hipotesis dengan banyak behavior sudah dipecah, dengan urutan pengerjaan dan alasannya.
- Tiap hipotesis punya kriteria sukses dan batas durasi.
- Tiga hipotesis buruk diperbaiki dengan penjelasan.

**Variasi tantangan:** ambil satu teknik ATT&CK yang relevan untuk sektor yang kamu minati. Caranya: setiap halaman group di ATT&CK (misalnya `attack.mitre.org/groups/G0xxx/`) memuat tabel "Techniques Used" berisi ID teknik, nama, dan prosedur singkat yang pernah dilaporkan untuk aktor itu, lengkap dengan referensi laporannya [S6]. Pilih aktor yang dilaporkan menargetkan sektormu, ambil satu teknik dari tabel itu, lalu baca prosedurnya sebagai bahan Behavior. Buka juga detection strategy di halaman teknik itu untuk ide Evidence. Tulis hipotesis ABLE untuk teknik itu di lab-mu, lalu nilai dengan jujur apakah Evidence-nya tersedia. Bila tidak, tulis rekomendasi telemetri (hubungkan ke Day 04).

## 4. Troubleshooting

Tabel ini memuat masalah yang sering muncul saat menulis dan menguji hipotesis. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Hunt tidak pernah selesai | Hipotesis terlalu luas | Persempit ke satu behavior dan satu lokasi (bagian 1.3) |
| Hasil hunt tidak bermakna | Hipotesis tidak bisa dibantah | Rumuskan ulang agar data bisa menyangkalnya (bagian 1.2) |
| Evidence tidak ada saat Execute | ABLE tidak dicek di awal | Konfirmasi Evidence ada sebelum menjalankan (bagian 1.5) |
| Hunt melebar ke banyak teknik | Memburu seluruh kill chain | Pecah menjadi beberapa hunt di backlog [S1] |
| Hipotesis terasa seperti tebakan | Tidak bersandar pada sumber | Hubungkan ke intel, ATT&CK, baseline, insiden, atau pengalaman (bagian 1.7) |
| Query Evidence kosong | Field DNS beda nama; data belum lama | Cek nama field EID 22 (`QueryName`) atau resolver (`query`); perpanjang rentang |
| Stacking DNS tidak pernah menemukan apa pun | Dikelompokkan per nama query penuh | Kelompokkan per domain induk (bagian 2.6) |
| Semua domain `.co.id` tergabung menjadi satu | Regex dua label terakhir | Pakai daftar suffix publik atau tangani TLD dua label secara khusus |
| Rentang abstract tidak bisa diulang | Retensi `dns` 30 hari terlewati | Simpan agregat dengan `outputlookup` saat abstract dibuat (bagian 2.6) |

## 5. Kesalahan umum dan jebakan

- Menulis topik dan menyebutnya hipotesis. Topik ("data exfiltration") harus ditajamkan ke pernyataan yang bisa dibantah [S1].
- Menyebut pencarian IOC dari brief sebagai hunt. Itu pencarian indikator (HMM1); hunt mengambil perilakunya (bagian 1.1).
- Hipotesis tentang niat aktor. Niat tidak terlihat di log; tulis perbuatannya [S4].
- Hipotesis tanpa Evidence yang benar-benar ada. Cek ketersediaan data sebelum Execute.
- Memburu seluruh kill chain alih-alih satu atau dua behavior [S1].
- Hipotesis berbasis IOC yang sebenarnya pencarian indikator (HMM1), bukan hunting TTP [S3].
- Actor dianggap wajib. Actor opsional; banyak hunt yang baik tidak menyebut aktor [S1][S2].
- Mengelompokkan query DNS per nama penuh (`BY host, QueryName`) lalu menyaring `queries > 100`. Tunneling menghasilkan nama yang hampir selalu baru, sehingga setiap nama hanya muncul sekali dan tidak pernah lolos filter. Yang menumpuk adalah domain induknya; kelompokkan di sana (bagian 2.6).
- Menganggap Sysmon EID 22 sebagai cakupan DNS seluruh perusahaan. Di PT JAB hanya 186 host, dan sekitar 60% workstation tidak ber-Sysmon; cakupan utama ada di log resolver (bagian 1.5).
- Membuat allowlist per domain induk saja. Allowlist yang terlalu lebar ikut menyembunyikan host lain yang tiba-tiba memakai domain yang sama; pakai kombinasi domain dan klien (bagian 2.6).
- `[komunitas, belum terkonfirmasi]` Praktisi sering menyarankan memulai dari hunt baseline di lingkungan baru untuk memahami data sebelum menulis hipotesis spesifik. Anjuran ini selaras dengan cara PEAK menempatkan hunt baseline, tetapi belum ditemukan sebagai pernyataan resmi di dokumen PEAK yang dirujuk Day ini; perlakukan sebagai praktik yang masuk akal, bukan aturan kerangka.

## 6. Catatan terkini

Bagian ini menampung detail versi, tanggal terbit, dan perubahan sumber yang berguna saat membuka dokumen aslinya, tetapi tidak mengubah cara menulis hipotesis di atas.

- PEAK memformalkan ABLE sebagai alat fase Prepare, dengan contoh kerja DNS exfiltration dan cryptominer [S1][S2]. Blog hypothesis-driven terbit 8 Mei 2023 (David Bianco) [S1]; contoh cryptominer terbit 19 Januari 2024, disusun bersama Cyber Security Agency of Singapore dan memakai dataset BOTSv3 [S2].
- Contoh cryptominer PEAK memetakan Behavior ke T1496 Resource Hijacking dan membiarkan Actor kosong, menunjukkan Actor memang opsional [S2]. Contoh itu masih memakai ID data source gaya lama (DS0013, DS0029) [S2].
- ATT&CK v20.0 dirilis 13 Oktober 2026, menggantikan v19.2 yang berlaku 28 April sampai 12 Oktober 2026 [S11]. Per v20.0: T1071.004 versi 1.4 (diubah 3 September 2026) [S7], T1048 versi 1.6 (diubah 3 September 2026, tiga sub-teknik) [S8], T1053.005 versi 1.8 (diubah 12 Mei 2026) [S9]. Halaman teknik kini memuat detection strategy (misalnya DET0400 untuk T1071.004 dan DET0441 untuk T1053.005) dengan analytic per platform [S7][S9][S10].
- ATT&CK v19 mengubah sebagian taksonomi, termasuk pemecahan taktik Defense Evasion; saat menulis Behavior, pakai ID teknik versi terbaru. Teknik yang dicabut (revoked) atau dideprekasi tetap punya halaman dengan keterangan penggantinya, jadi cek status itu sebelum memakai ID dari laporan lama [S6].
- Halaman Sysmon di Microsoft Learn diperbarui 10 September 2026; EID 22 tetap tersedia sejak Windows 8.1, dan EID 3 (network connection) tetap nonaktif secara default [S12].
- Data tetap hambatan utama (SANS 2026, Day 01 bagian 1.7), sehingga menilai ketersediaan Evidence adalah bagian wajib menulis hipotesis.

## 7. Cheat sheet

```
IOC       daftar domain/IP = pencarian indikator (HMM1), dikerjakan L1; hit -> triage/IR
          hunt mengambil PERILAKU dari brief, bukan alamatnya
TAJAM     topik -> riset jejak -> pilih 1 metode (behavior) -> tambah konteks (data/aset/lokasi)
UJI       bisa dibuktikan ATAU dibantah oleh data ; tidak kaku, disempurnakan saat investigasi
          niat ("ingin mencuri") tidak bisa diuji -> tulis perbuatan yang teramati
ABLE      Actor (opsional) | Behavior (1-2 TTP) | Location (di mana) | Evidence (log apa, seperti apa)
CEK       Behavior+Location+Evidence terisi & Evidence terbukti ada (sumber, field, cakupan)
SUMBER    intel | ATT&CK | baseline | keahlian domain | insiden historis | red team/crown jewel | celah use case
URUTAN    relevansi | dampak | Evidence siap | data hilang bila ditunda (retensi) | celah deteksi
SCOPE     batas durasi (mis. 3 hari) + rentang data (biasanya >=30 hari) + kriteria sukses
ANTIPOLA  terlalu luas | tak bisa dibantah | hanya IOC | tanpa Evidence | tebakan | seluruh kill chain | niat
DNS       stats dc(sub) avg(len(sub)) dc(src) values(record_type) BY parent   (BUKAN BY QueryName)
          label <= 63, nama <= 255 ; FP: antivirus/telemetri/CDN -> allowlist domain+klien
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "L1 sudah mencocokkan 40 domain dan IP dari brief forum ke index `proxy`, `dns`, dan `firewall`, dan tidak ada hit. Jadi hunt untuk kampanye itu selesai dengan hasil tidak ditemukan." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Pencocokan IOC adalah pencarian indikator (HMM1), bukan hunt. Hasil "tidak ada hit" hanya berarti 40 indikator itu tidak muncul di data yang masih tersimpan, dan `proxy` serta `dns` hanya menyimpan 30 hari. Hasil itu tidak mengatakan apa pun tentang infrastruktur baru penyerang yang sama. Hunt untuk kampanye itu adalah hipotesis tentang perilakunya, yaitu DNS tunneling dan scheduled task. Lihat bagian 1.1.

</details>

**2. Skenario keputusan.** Gilang mengusulkan tiga kalimat untuk backlog. Mana yang merupakan hipotesis yang bisa diuji?

- A. "Kelompok di brief forum ingin mencuri data pelanggan PT JAB."
- B. "Ada host PT JAB yang mengirim banyak query dengan subdomain panjang dan bervariasi ke satu domain induk lewat resolver internal, tanpa memicu alert."
- C. "Pasti ada penyerang di jaringan telekomunikasi kita, kita harus menemukannya."

<details><summary>Jawaban</summary>

B. Kalimat itu menyebut perilaku yang teramati, lokasinya, dan secara implisit data yang akan membuktikan atau membantahnya (log resolver); bila tidak ada domain induk dengan pola itu, hipotesisnya gugur untuk rentang yang diperiksa. A keliru karena menyatakan niat, dan niat tidak terlihat di log. C keliru karena tidak bisa dibantah: tidak ada hasil data apa pun yang bisa membuktikannya salah. Lihat bagian 1.2 dan 1.3.

</details>

**3. Pertanyaan jebakan.** "ABLE untuk `HUNT-2027-003` belum lengkap karena brief tidak menyebut nama aktor. Hunt itu belum boleh masuk status siap dijalankan." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Actor adalah elemen opsional; PEAK menyebut banyak hal tidak terikat aktor tertentu, dan slide PEAK menulis Actor "not always applicable". Contoh cryptominer PEAK juga membiarkan Actor kosong. Yang menentukan kesiapan adalah Behavior, Location, dan Evidence terisi, serta Evidence terbukti tersedia lewat query cepat, dan untuk `HUNT-2027-003` ketiganya sudah dipenuhi. Lihat bagian 1.4.

</details>

**4. Skenario keputusan.** Kamu hanya punya satu hari hunting minggu ini. Brief menyebut DNS tunneling dan scheduled task. Langkah mana yang paling tepat?

- A. Gabungkan keduanya menjadi satu hunt "kampanye forum" supaya selesai dalam sehari.
- B. Kerjakan `HUNT-2027-003` dulu karena data `dns` hanya bertahan 30 hari dan Evidence-nya sudah terbukti; tulis `HUNT-2027-004` sebagai abstract dan jalankan setelah audit 4698 dicek.
- C. Kerjakan `HUNT-2027-004` dulu karena Sysmon EID 1 ada di semua 214 host ber-Sysmon, sehingga cakupannya paling luas.

<details><summary>Jawaban</summary>

B. Data DNS menyusut setiap hari karena retensi 30 hari, dan Evidence-nya sudah dikonfirmasi lewat query, sedangkan data untuk scheduled task tidak mendesak hilang dan status audit 4698 belum dicek. A keliru karena dua perilaku itu punya data, lokasi, dan false positive yang berbeda; satu hunt gabungan sulit punya kriteria sukses yang jelas. C keliru karena EID 1 hanya menangkap task yang dibuat lewat `schtasks.exe`; jalur API dan WMI butuh 4698 yang belum dicek, jadi cakupan "214 host" menyesatkan. Lihat bagian 1.6 dan 2.7.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Gilang Ramadhan (analyst L1), dalam tiga kalimat, kenapa 40 IOC dari brief tetap dia cari hari ini walaupun itu bukan hunt.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Mencari 40 domain dan IP itu murah dan cepat, dan kalau ada hit kita langsung punya alert untuk di-triage, bahkan mungkin insiden. Tapi hasil 'tidak ada hit' hanya berlaku untuk 30 hari data proxy dan DNS yang masih tersimpan, dan penyerang bisa mengganti domain dan IP-nya kapan saja. Karena itu perilakunya, DNS tunneling dan scheduled task, kita jadikan hipotesis terpisah yang tetap berguna walaupun semua IOC di brief sudah tidak dipakai."

Kesalahan yang sering muncul:
- Mengatakan IOC tidak berguna, padahal pencariannya tetap wajib dan murah.
- Lupa menyebut batas retensi 30 hari, sehingga "tidak ada hit" terdengar seperti "aman".
- Tidak menjelaskan bahwa hit IOC masuk jalur triage atau IR, bukan hunt.

</details>

**6. Pertanyaan jebakan.** "Query `index=sysmon EventCode=22 | stats count BY host, QueryName | where count > 100` adalah cara yang baik untuk memburu DNS tunneling, karena tunneling menghasilkan banyak query." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Tunneling memang menghasilkan banyak query, tetapi setiap query memakai subdomain yang hampir selalu baru, sehingga setiap nama penuh hanya muncul sekali dan tidak pernah lolos `count > 100`. Yang menumpuk adalah domain induknya, jadi stacking harus dikelompokkan per domain induk dengan jumlah subdomain unik dan panjang subdomain. Selain itu, Sysmon EID 22 di PT JAB hanya mencakup 186 host, sehingga cakupan utama tetap log resolver. Lihat bagian 2.6 dan 5.

</details>

**7. Interview question (English).** "You receive a threat intel report with a list of IOCs and a short description of the attacker's techniques. How do you turn it into a hunt?"

<details><summary>Sample answer</summary>

"I split the report into two pieces of work. The IOCs go straight into an indicator sweep against our historical data, which is quick and done by the SOC, with the caveat that our DNS and proxy logs only go back 30 days. The technique description is where the hunt comes from. I research what the technique looks like in our data, then write a testable hypothesis using ABLE: the behavior as something observable, where in the network it would show up, and which data source would prove or disprove it, with the actor as optional context. Before I put it in the backlog as ready, I run a quick query to confirm the evidence actually exists, for example that all our DNS resolvers are logging and which hosts send Sysmon DNS events. If the report mentions two techniques, I make them two hunts and start with the one whose data expires first. A good hypothesis is one the data can disprove; if it can't be disproven, it's a belief, not a hunt."

What makes this answer strong: it separates indicator matching from behavior hunting, names a concrete framework (ABLE), checks evidence availability before committing, prioritizes with a real constraint like retention, and ends with the falsifiability test that interviewers look for.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Splunk: Hypothesis-Driven Hunting with the PEAK Framework (David Bianco) | https://www.splunk.com/en_us/blog/security/peak-hypothesis-driven-threat-hunting.html | sekunder (blog vendor, penulis kerangka) | 2023-05-08; diakses 2026-10-08, dicek ulang 2026-10-18 | Tinggi. ABLE, penajaman topik, langkah Prepare/Execute/Act, batas durasi tiga hari |
| S2 | Splunk: Hypothesis-Driven Cryptominer Hunting with PEAK (David Bianco) | https://www.splunk.com/en_us/blog/security/hypothesis-driven-cryptominer-hunting-with-peak | sekunder | 2024-01-19; diakses 2026-10-08, dicek ulang 2026-10-18 | Sedang-tinggi. Contoh ABLE nyata, Actor opsional, rentang minimal 30 hari, BOTSv3 |
| S3 | TaHiTI whitepaper (pemicu hunt) | https://www.betaalvereniging.nl/wp-content/uploads/2026/03/TaHiTI-Threat-Hunting-Methodology-whitepaper.pdf | primer | diakses 2026-10-07 (Day 01) | Tinggi. Daftar pemicu hunt, fokus tiga lapisan atas Pyramid of Pain |
| S4 | Splunk .conf23: Blue Team Academy: Cybersecurity Defense Analyst, The Art of Investigation and Threat Hunting With Splunk (SEC1584B), slides | https://conf.splunk.com/files/2023/slides/SEC1584B.pdf | primer (materi workshop, salah satu penulis kerangka sebagai pembicara) | 2023; diakses 2026-10-08, dicek ulang 2026-10-18 | Sedang-tinggi. Slide ABLE ("Are you ABLE to hunt?"), masukan topik, contoh hipotesis yang tidak bisa dan bisa diuji |
| S5 | Day 01-02 Threat-Hunting-Notes | (lokal) | rujukan internal | 2026-10-18 | Siklus hunt, tipe hunt, Pyramid of Pain, HMM |
| S6 | MITRE ATT&CK: Groups | https://attack.mitre.org/groups/ | primer | konten v19.2; diakses 2026-10-10 | Tinggi. Struktur halaman group dan teknik, status revoked/deprecated |
| S7 | MITRE ATT&CK: T1071.004 Application Layer Protocol: DNS | https://attack.mitre.org/techniques/T1071/004/ | primer | v1.4, diubah 2026-09-03; konten ATT&CK v20.0; diakses 2026-10-18 | Tinggi. Definisi DNS tunneling untuk C2, record TXT/A, DET0400 |
| S8 | MITRE ATT&CK: T1048 Exfiltration Over Alternative Protocol | https://attack.mitre.org/techniques/T1048/ | primer | v1.6, diubah 2026-09-03; diakses 2026-10-18 | Tinggi. DNS sebagai protokol alternatif, beda dengan kanal C2 |
| S9 | MITRE ATT&CK: T1053.005 Scheduled Task/Job: Scheduled Task | https://attack.mitre.org/techniques/T1053/005/ | primer | v1.8, diubah 2026-05-12; diakses 2026-10-18 | Tinggi. Taktik, jalur pembuatan task, task tersembunyi, DET0441 |
| S10 | MITRE ATT&CK: DET0400 Behavioral Detection of DNS Tunneling and Application Layer Abuse | https://attack.mitre.org/detectionstrategies/DET0400/ | primer | konten v20.0; diakses 2026-10-18 | Tinggi. Analytic AN1121 sampai AN1125, parameter yang bisa disetel |
| S11 | MITRE ATT&CK: Versions of ATT&CK | https://attack.mitre.org/resources/versions/ | primer | diakses 2026-10-18 | Tinggi. v20.0 sejak 2026-10-13; v19.2 2026-04-28 sampai 2026-10-12 |
| S12 | Microsoft Learn: Sysmon (Sysinternals) | https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon | primer | diperbarui 2026-09-10; diakses 2026-10-18 | Tinggi. EID 22 sejak Windows 8.1, EID 3 nonaktif default, ProcessGuid |
| S13 | EventSentry: Sysmon Event ID 22 | https://system32.eventsentry.com/sysmon/event/22 | sekunder (referensi vendor) | diakses 2026-10-18 | Sedang. Daftar field EID 22; deskripsi per field tidak tersedia |
| S14 | Microsoft Learn: 4698(S) A scheduled task was created | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4698 | primer (dokumentasi arsip) | diperbarui 2026-04-27; diakses 2026-10-18 | Tinggi. Subcategory audit, field, field tambahan Windows 10 1903, rekomendasi task di root |
| S15 | Unit 42: Detecting DNS Tunneling Campaigns in the Wild (Ruian Duan, Daiping Liu) | https://unit42.paloaltonetworks.com/dns-tunneling-in-the-wild/ | sekunder (riset vendor) | 2023-10-13; diakses 2026-10-18 | Sedang-tinggi. Mekanisme encoding, tipe record, pemakaian sah oleh vendor keamanan |
| S16 | IETF RFC 1035: Domain Names, Implementation and Specification | https://www.rfc-editor.org/rfc/rfc1035 | primer (standar) | November 1987; diakses 2026-10-18 | Tinggi. Batas label 63 oktet dan nama 255 oktet |
| S17 | Splunk Docs: CIM 6.4 Network Resolution (DNS) data model | https://help.splunk.com/en/data-management/common-information-model/6.4/data-models/network-resolution-dns | primer | CIM 6.4; diakses 2026-10-18 | Tinggi. Field `query`, `record_type`, `reply_code`, `src` |
| S18 | SANS: Generating Hypotheses for Successful Threat Hunting (Robert M. Lee, David Bianco) | https://www.sans.org/white-papers/37172 | sekunder (white paper) | 2016-08-15; diakses 2026-10-18 | Sedang. Hanya halaman abstrak yang dibaca: tiga jenis hipotesis disebut tanpa rincian |

**Catatan sumber:** isi slide [S4] dibaca dari berkas slide; slide tidak menuliskan aturan kesiapan secara eksplisit, jadi cek "siap dijalankan" di bagian 1.4 adalah cara catatan ini memakai judul slide ABLE. Daftar field Sysmon EID 22 [S13] berasal dari referensi pihak ketiga; cocokkan dengan skema `sysmon -s` di lab-mu, dan cek nama field `QueryName` setelah normalisasi add-on. Klaim bahwa EID 22 mungkin tidak mencatat program yang membangun paket DNS sendiri belum dikonfirmasi sumber primer dan perlu diuji di lab. Pemetaan exfil lewat kanal C2 DNS yang sama ke T1041 adalah penerapan definisi T1048 [S8]; cek halaman T1041 bila dipakai di laporan formal. Rincian tiga jenis hipotesis di [S18] tidak dibaca karena makalah lengkapnya tidak dibuka. Seluruh isi PT JAB (brief forum, 40 IOC, angka resolver, 186 dari 214 host, domain `avcloud.example`, host `jkt-proxy01`, `HUNT-2027-002` sampai `-004`) adalah penerapan catatan ini pada organisasi fiktif, bukan hasil eksekusi nyata.
