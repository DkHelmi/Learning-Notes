---
day: 12
title: 'Capstone CTI: memprofilkan satu ancaman end-to-end, template brief dua halaman, dan pemetaan ke hipotesis hunting'
researched_on: 2026-10-10
versions_checked: 'MITRE ATT&CK v19; FIRST TLP 2.0; STIX/TAXII 2.1; rujukan Day 01-11'
---

# Day 12: Capstone CTI

Cakupan: satu latihan terpadu dengan skenario fiktif lengkap, dari PIR dan bahan mentah sampai brief dua halaman, pemetaan ke hipotesis hunting, contoh produk akhir yang bisa dicontoh, rubrik untuk menilai hasil kerjamu sendiri, dan rencana lanjut setelah capstone.

## Ide inti

Profil ancaman yang berguna menjawab pertanyaan satu konsumen dengan bahan yang kualitasnya campur aduk, lalu berakhir di tindakan yang punya pemilik dan tenggat. Capstone ini tidak menambah materi baru. Yang dilatih adalah urutan kerja dan disiplin dari Day 01-11: kapan berhenti mengumpulkan, bagaimana menimbang bukti, dan bagaimana menulis sesuatu yang membuat orang lain bertindak, di bawah kondisi yang mirip pekerjaan nyata (banyak sumber, keandalan berbeda-beda, informasi internal yang belum jelas artinya, dan tenggat). Pelajaran terpenting skenarionya: nilai terbesar CTI sering bukan brief yang rapi, melainkan menghubungkan intelijen eksternal dengan data internal yang sudah ada tetapi belum dibaca dengan konteks.

Kamu sudah mengenal ritme ini dari menangani insiden. Saat triage menemukan indikasi kompromi, kamu tidak menunggu laporan insiden selesai sebelum memberi tahu tim containment; pesan singkat dikirim dulu, laporan rapi menyusul. Laporan akhirnya memisahkan apa yang terlihat di log dari kesimpulanmu, menyebut seberapa yakin kamu (seperti confidence pada alert), dan setiap temuan berakhir di tindakan. Bedanya, profil ancaman dimulai dari pertanyaan konsumen tentang ancaman di luar, bukan dari alert, dan bisa selesai tanpa ada insiden sama sekali.

```
PIR (pertanyaan CISO) + bahan A-F
  -> konsumen dan urgensi          : ada indikasi internal? -> pesan cepat ke SOC/IR sekarang
  -> nilai bahan (Admiralty)       -> pisahkan fakta, penilaian, dan klaim tak terverifikasi
  -> ACH untuk pertanyaan terbuka  -> bukti pembeda yang harus dicari
  -> Diamond + ATT&CK (procedure)  -> telemetri dan status deteksi per tahap
  -> brief 2 halaman (BLUF, TLP) + lampiran teknis untuk SOC/IR
  -> hipotesis hunting             -> hasil hunt memperbarui brief
  -> rubrik penilaian diri         -> Day yang perlu diulang
```

Situasi yang dipakai sepanjang Day ini: Jumat, 9 Oktober 2026, CISO PT Logistik Contoh (PT LC, perusahaan logistik fiktif dengan gudang di Jakarta, Surabaya, dan Medan) baru membaca berita tentang serangan ransomware ke perusahaan logistik lain. Ia mengirim pesan ke tim CTI:

> "Saya butuh brief untuk rapat direksi Selasa depan. Tolong jawab: (1) ancaman ransomware mana yang kemungkinan mengincar kita dalam enam bulan ke depan, (2) lewat jalur masuk apa, (3) apakah kontrol kita saat ini cukup untuk mendeteksi atau mencegahnya, dan (4) apa yang perlu diputuskan direksi."

Pertanyaan 1-3 adalah isi PIR-02 yang sudah disetujui CISO (bagian 1.2). Pertanyaan 1 dijawab lewat penilaian bahan dan Diamond (bagian 2.1 dan 2.3), pertanyaan 2 lewat tabel procedure ke ATT&CK (bagian 2.3), pertanyaan 3 lewat kolom status deteksi dan hipotesis hunting (bagian 2.3 dan 2.5), dan pertanyaan 4 lewat rekomendasi di brief (bagian 2.4). Ada satu hal yang tidak diminta CISO tetapi paling mendesak: data internal di bagian 1.3 menunjukkan kampanye ini mungkin sudah sampai ke PT LC (bagian 2.1 dan 2.2).

Cara terbaik memakai Day ini: kerjakan lab di bagian 3 lebih dulu dengan bahan di bagian 1, baru bandingkan hasilmu dengan contoh pengerjaan di bagian 2.

**Kapan relevan:** menguji kesiapan setelah Day 01-11, sebagai kerangka untuk profil ancaman nyata, dan sebagai contoh portofolio.
**Kapan bukan jawaban:** capstone tidak menambah konsep baru; bila satu langkah terasa asing, kembali ke Day asalnya (peta kriteria ke Day ada di bagian 3.3). Skenario fiktif juga lebih rapi daripada kenyataan: profil ancaman nyata butuh lebih banyak sumber dan atribusi yang lebih hati-hati.

## 1. Skenario dan bahan latihan

Seluruh organisasi, orang, aktor, domain, IP, nomor CVE, dan angka di bagian ini fiktif. IOC di-defang.

### 1.0 Istilah di Day ini

Capstone tidak memperkenalkan istilah baru. Tabel ini mengumpulkan istilah dari Day 02-11 yang dipakai di latihan supaya kamu tidak perlu membuka Day asalnya; istilah dasar dari Day 01 (CTI, IOC, TTP, konsumen) tidak diulang. Kolom padanan memakai analogi SOC yang sama di semua Day CTI.

| Istilah | Arti singkat | Padanan di SOC |
|---|---|---|
| PIR | Priority intelligence requirement: pertanyaan prioritas yang disetujui pengambil keputusan | Use case request: pertanyaan yang ingin dijawab sebelum menulis rule |
| Admiralty | Kode dua bagian untuk tiap bahan: keandalan sumber (A-F) dan kredibilitas informasi (1-6); F dan 6 berarti belum bisa dinilai | Menimbang sumber alert: sensor EDR yang terkonfigurasi benar tidak sama bobotnya dengan cerita pengguna lewat telepon |
| Fakta vs penilaian | Fakta adalah observasi; penilaian adalah kesimpulan analis yang disertai kemungkinan dan keyakinan | Isi log vs kesimpulan triage ("benign") |
| Kemungkinan dan keyakinan | Dua pernyataan terpisah: seberapa mungkin sesuatu terjadi, dan seberapa kuat dasar penilaiannya | Confidence pada alert |
| ACH | Analysis of Competing Hypotheses: matriks bukti terhadap beberapa hipotesis, dengan fokus pada bukti yang tidak konsisten | Triage dengan membandingkan semua penjelasan alert, lalu mencari bukti yang menggugurkan masing-masing |
| Diamond Model | Empat sudut sebuah intrusi: adversary, capability, infrastructure, victim | Ringkasan insiden: siapa, memakai apa, lewat mana, ke siapa |
| Procedure | Cara spesifik aktor menjalankan sebuah technique ATT&CK | Rantai proses atau command line persis yang terlihat di EDR, bukan nama tekniknya |
| BLUF | Bottom Line Up Front: kesimpulan dan tindakan ditulis di awal | Baris pertama email eskalasi: apa yang terjadi dan apa yang diminta |
| TLP | Traffic Light Protocol 2.0: label batas berbagi (CLEAR, GREEN, AMBER, AMBER+STRICT, RED) | Aturan distribusi laporan insiden: boleh diteruskan ke siapa |
| Lampiran teknis | Bagian terpisah untuk SOC/IR berisi TTP, IOC berkonteks, dan tindakan; boleh berlabel lebih ketat dari brief | Paket IOC dan TTP yang dilampirkan ke tiket IR |
| Hipotesis hunting | Pernyataan "bila ... maka ..." yang bisa diuji dengan data yang tersedia, lengkap dengan kriteria selesai | Hunt berbasis hipotesis |

### 1.1 Organisasi

Profil ini menentukan apa arti "relevan" bagi PT LC: sektor, kawasan, sistem yang menjadi sasaran dampak, dan celah telemetrinya.

PT Logistik Contoh (PT LC) adalah perusahaan logistik dengan sekitar 3.000 karyawan, gudang di Jakarta, Surabaya, dan Medan, dan sistem manajemen gudang (WMS) on-premise yang menjadi tulang punggung operasi. Akses jarak jauh karyawan lewat appliance VPN merek fiktif "GateSecure". EDR terpasang di sekitar 70 persen endpoint; sisanya laptop gudang lama. SIEM menerima log email gateway, proxy, DNS, VPN, dan log Windows dari server.

Tim CTI terdiri dari dua orang dan melapor ke CISO. Konsumen produk CTI: CISO dan direksi (strategis), SOC lead dan IR (taktis), dan tim infrastruktur (patching).

### 1.2 PIR dan tenggat

Pesan CISO di bagian Ide inti bersandar pada PIR yang sudah disetujui sebelumnya, sehingga tim CTI tidak perlu menebak pertanyaannya.

PIR-02 yang disetujui CISO: "Ancaman ransomware mana yang kemungkinan menargetkan PT LC dalam enam bulan ke depan, lewat jalur masuk apa, dan apakah kontrol kita saat ini cukup untuk mendeteksi atau mencegahnya?"

Pemicu: pada Jumat, 9 Oktober 2026, CISO meminta brief untuk rapat direksi Selasa depan, setelah membaca berita tentang serangan ransomware ke perusahaan logistik lain.

### 1.3 Bahan mentah

Enam bahan berikut tersedia saat tim CTI mulai bekerja, dengan kualitas yang sangat berbeda. Baca semuanya sebelum menilai; bahan yang paling penting belum tentu yang paling panjang.

**Bahan A: laporan vendor A (TLP:CLEAR, terbit 8 Oktober 2026).** Laporan riset tentang kampanye yang mereka sebut "FICTA SPIDER". Isinya: enam korban perusahaan logistik di Indonesia, Malaysia, dan Thailand antara Juli dan Oktober 2026; akses awal lewat email bertema faktur dengan lampiran zip berisi berkas .js; berkas dijalankan wscript; persistence lewat scheduled task dari ProgramData; komunikasi HTTPS dengan interval seragam; data diunggah ke layanan cloud storage dengan rclone; lalu enkripsi berkas di share jaringan dan penghapusan shadow copy. IOC: bad-logistics[.]example, invoice-check[.]example, 203.0.113[.]50. Metodologi: telemetri EDR dari enam pelanggan. Laporan dibuka dengan kalimat "salah satu kelompok paling berbahaya di kawasan".

**Bahan B: laporan vendor B (TLP:CLEAR, terbit 2 Oktober 2026).** Laporan tentang "Storm-0000". Isinya: korban di logistik dan ritel; dua jalur masuk, yaitu email dengan lampiran .js dalam zip dan eksploitasi kerentanan CVE-2026-99999 pada appliance VPN GateSecure; dua keluarga ransomware, salah satunya sama dengan bahan A. Laporan menyebut "kemungkinan didukung negara" tanpa menjelaskan dasarnya. Tidak ada metodologi.

**Bahan C: email ISAC logistik (TLP:GREEN, 7 Oktober 2026).** Dua anggota ISAC melaporkan menerima email berlampiran zip berisi .js bertema faktur dalam seminggu terakhir. Satu anggota menyebut satu host terinfeksi dan sudah diisolasi. Pengirim email memakai domain invoice-check[.]example.

**Bahan D: data internal PT LC (internal).**

```
Gateway email, 2026-10-07 (keluaran ilustrasi)
  42 email dari billing@invoice-check[.]example ke 11 penerima di divisi keuangan
  lampiran: Faktur_Okt.zip (berisi Faktur_Okt.js) ; status: delivered (zip tidak diperiksa isinya)

EDR, 2026-10-07 14:12 WIB, WS-021 (keuangan)
  explorer.exe -> wscript.exe "C:\Users\rina\Downloads\Faktur_Okt\Faktur_Okt.js"
  alert: "Script execution from user download folder" ; severity: low ; status: closed (benign?)
  catatan analis SOC: "pengguna bilang hanya membuka faktur, tidak terjadi apa-apa"

DNS, 2026-10-07 14:12-14:13 WIB
  WS-021 query bad-logistics.example (3x)

Proxy, 2026-10-07 s.d. 2026-10-09
  WS-021 -> 203.0.113.50:443  : tidak ada entri
  WS-021 -> tujuan lain        : normal

Inventaris
  Appliance VPN GateSecure versi 9.2 (terdampak CVE-2026-99999 menurut vendor GateSecure) ; patch belum dipasang
```

**Bahan E: unggahan di forum publik (tidak terverifikasi).** Akun anonim di forum publik mengklaim "LOGI-FICTA sudah masuk ke tiga perusahaan logistik besar di Jakarta, salah satunya PT LC". Tidak ada bukti yang dilampirkan.

**Bahan F: katalog kerentanan yang dieksploitasi.** CVE-2026-99999 (GateSecure) masuk katalog kerentanan yang terbukti dieksploitasi pada 30 September 2026. Vendor GateSecure menerbitkan patch pada 25 September.

## 2. Contoh pengerjaan dan produk akhir

Bagian ini adalah satu contoh jawaban untuk pesan CISO, dan semua isinya fiktif seperti bagian 1. Jawabanmu boleh berbeda selama alasannya jelas dan jujur tentang keyakinan.

### 2.1 Menilai bahan

Sebelum menjawab pertanyaan CISO, keenam bahan ditimbang lebih dulu. Tabel ini memberi kode Admiralty per bahan; perhatikan kolom terakhir, karena apa yang tidak diambil sama pentingnya dengan apa yang diambil.

| Bahan | Admiralty | Alasan | Yang diambil | Yang tidak diambil |
|---|---|---|---|---|
| A | B2 | Vendor dengan rekam jejak, data telemetri sendiri, konsisten dengan C | Procedure, korban, IOC | Superlatif pembuka |
| B | B3 | Vendor dikenal, tetapi tanpa metodologi; klaim sponsor negara tanpa dasar | Jalur masuk VPN, CVE, overlap ransomware | Klaim sponsor negara |
| C | B2 | ISAC dengan anggota langsung terdampak; isi cocok dengan A | Konfirmasi kampanye aktif, domain pengirim | Tidak ada |
| D | A1 | Data sendiri, bisa diperiksa ulang | Fakta email, eksekusi .js, query DNS | Kesimpulan "benign" analis SOC (belum diuji) |
| E | F6 | Akun anonim, tidak ada bukti, tidak bisa dinilai | Tidak ada, kecuali sebagai pemicu pemeriksaan | Klaim bahwa PT LC sudah dibobol |
| F | A1 | Katalog resmi berbasis bukti eksploitasi | Status dieksploitasi, tanggal | Tidak ada |

Hal pertama yang terlihat setelah penilaian: bahan D jauh lebih penting daripada yang disadari. Alert EDR yang ditutup sebagai benign, ditambah query DNS ke domain dari laporan A, adalah indikasi bahwa procedure akses awal kampanye ini sudah terjadi di PT LC. Brief untuk direksi tidak boleh menunggu; SOC dan IR harus diberi tahu hari itu juga.

Keputusan analis yang baik di titik ini: berhenti sebentar dari menulis brief dan menulis pesan singkat ke SOC lead dan IR (TLP:AMBER+STRICT) yang meminta WS-021 diperiksa ulang. Ini contoh CTI yang paling bernilai: menghubungkan intelijen eksternal dengan data internal yang sudah ada tetapi belum dibaca dengan konteks.

### 2.2 Pertanyaan analitis dan ACH

Penilaian bahan memunculkan pertanyaan yang tidak ada di pesan CISO, tetapi menentukan isi brief. Pertanyaan terbuka: apa yang terjadi di WS-021 pada 7 Oktober?

Matriks berikut menimbang empat hipotesis terhadap bukti dari bahan D. Baca per kolom dan cari tanda TK, karena bukti yang tidak konsisten yang menggugurkan sebuah hipotesis.

| Bukti | H1: infeksi LOGI-FICTA, berhenti di tahap awal | H2: infeksi LOGI-FICTA, berlanjut tanpa terlihat | H3: berkas dijalankan tetapi gagal (terblokir atau rusak) | H4: aktivitas tidak terkait kampanye |
|---|---|---|---|---|
| Email dari domain yang disebut C | K | K | K | TK |
| wscript menjalankan .js dari Downloads | K | K | K | TK |
| Query DNS ke domain C2 dari laporan A | K | K | N | TK |
| Tidak ada koneksi proxy ke IP C2 | K | N | K | N |
| Tidak ada alert EDR lanjutan | K | N | K | N |
| EDR hanya mencatat eksekusi, tanpa event scheduled task (cek belum dilakukan) | N | N | N | N |

K = konsisten, TK = tidak konsisten, N = netral atau tidak membedakan.

Cara membaca: H4 gugur karena tiga bukti tidak konsisten. H1, H2, dan H3 tidak bisa dibedakan dengan bukti yang ada. Bukti yang paling membedakan belum dikumpulkan: apakah ada scheduled task baru di WS-021, apakah ada koneksi HTTPS periodik ke tujuan lain, dan apakah ada unggahan besar. Kesimpulan ACH di sini bukan memilih hipotesis, melainkan menentukan bukti apa yang harus dicari. Itulah alasan hunt H1 dan H2 di bagian 2.5.

Satu catatan bias: setelah membaca laporan A, mudah melihat semua bukti sebagai konfirmasi H2 (skenario terburuk). Ketiadaan koneksi ke IP C2 justru bukti yang menahan kesimpulan itu.

### 2.3 Diamond dan ATT&CK

Pertanyaan CISO pertama dan kedua (ancaman mana, lewat jalur apa) dijawab dengan memetakan kampanye ke Diamond Model dan ATT&CK pada tingkat procedure.

```
Diamond (kampanye LOGI-FICTA, sudut pandang PT LC)
  Adversary     : cluster FICTA SPIDER (vendor A) / tumpang tindih sebagian dengan Storm-0000 (vendor B)
                  motivasi finansial [kemungkinan besar, keyakinan tinggi]
  Capability    : ransomware-lab ; .js dropper ; rclone ; scheduled task
  Infrastructure: domain bertema faktur/logistik baru didaftarkan ; VPS ; layanan cloud storage
  Victim        : logistik ID/MY/TH ; divisi keuangan sebagai penerima email ; WMS sebagai sasaran dampak
```

Tabel procedure berikut menjawab pertanyaan ketiga (apakah kontrol cukup). Kolom terakhir, status deteksi PT LC, nantinya menjadi bagian kondisi kontrol di brief.

| Tahap | Procedure | ATT&CK | Telemetri PT LC | Status deteksi PT LC |
|---|---|---|---|---|
| Akses awal | Zip berisi .js bertema faktur | T1566.001 | Gateway email | Tidak ada (zip tidak diperiksa) |
| Akses awal (alternatif, bahan B) | Eksploitasi CVE-2026-99999 di VPN | T1190, lalu T1133 | Log VPN | Tidak ada; patch belum dipasang |
| Eksekusi | wscript menjalankan .js dari Downloads | T1204.002, T1059.007 | EDR (70% endpoint) | Ada, severity rendah, ditutup sebagai benign |
| Persistence | Scheduled task dari ProgramData | T1053.005 | EDR, Security 4698 di server | Sebagian |
| C2 | HTTPS interval seragam | T1071.001 | Proxy, DNS | Tidak ada |
| Exfiltration | rclone ke cloud storage | T1567.002 | Proxy | Tidak ada |
| Impact | Hapus shadow copy, enkripsi share | T1490, T1486 | EDR, log server | Ada untuk T1490; belum teruji |

### 2.4 Produk akhir: brief dua halaman

Brief ini menjawab keempat pertanyaan CISO, termasuk keputusan yang diminta dari direksi. Brief ditulis Senin, 12 Oktober 2026, setelah SOC memeriksa ulang WS-021 dan menemukan scheduled task mencurigakan yang kemudian dihapus dan host di-reimage. Brief menggabungkan bahan A-F dengan hasil pemeriksaan itu.

```
TLP:AMBER
CTI-2026-044 | 12 Oktober 2026 | Tim CTI PT LC | Menjawab PIR-02 | Keyakinan keseluruhan: SEDANG

BRIEF ANCAMAN: KAMPANYE RANSOMWARE LOGI-FICTA TERHADAP SEKTOR LOGISTIK

BLUF
PT LC sudah menjadi sasaran kampanye ransomware LOGI-FICTA: pada 7 Oktober satu laptop
divisi keuangan terinfeksi lewat lampiran email, dan infeksi itu dihentikan pada
10 Oktober sebelum ada tanda pencurian data atau enkripsi. Kami menilai sangat mungkin
(keyakinan sedang) kampanye ini akan mencoba lagi dalam tiga bulan ke depan, lewat email
yang sama atau lewat celah pada VPN kita yang belum ditambal. Kami meminta dua keputusan
minggu ini: pemasangan patch VPN di luar jadwal pemeliharaan, dan pemblokiran lampiran
skrip di dalam arsip email.

1. APA YANG TERJADI DI PT LC
[Fakta] 7 Okt: 42 email faktur palsu diterima 11 staf keuangan; satu lampiran dibuka di
  laptop WS-021. Laptop menghubungi domain milik penyerang.
[Fakta] 10 Okt: pemeriksaan ulang menemukan mekanisme persistence penyerang di WS-021.
  Laptop diisolasi dan dipasang ulang. Tidak ditemukan pergerakan ke sistem lain
  dalam log yang tersedia.
[Penilaian] Kemungkinan besar (keyakinan sedang) penyerang belum melangkah lebih jauh.
  Keyakinan tidak tinggi karena 30% endpoint belum terpasang EDR.

2. SIAPA ANCAMANNYA
Kelompok kriminal bermotif uang yang dilacak vendor keamanan dengan nama FICTA SPIDER
dan Storm-0000 (cakupannya tumpang tindih sebagian). Sejak Juli 2026 mereka menyerang
setidaknya enam perusahaan logistik di Indonesia, Malaysia, dan Thailand [sumber B2].
Pola mereka: mencuri data lebih dulu, lalu mengenkripsi sistem dan memeras korban.
[Penilaian] Hampir pasti bermotif finansial (keyakinan tinggi). Klaim bahwa kelompok ini
  didukung negara tidak kami dukung karena tidak ada dasar yang dijelaskan sumbernya.

3. KENAPA PENTING BAGI PT LC
- Profil korban (logistik, kawasan ini, sistem gudang) cocok dengan PT LC.
- Korban lain melaporkan gangguan operasional gudang lebih dari satu minggu [sumber B2].
- Jalur masuk kedua, celah pada appliance VPN GateSecure, sudah terbukti dieksploitasi
  sejak akhir September [sumber A1]. VPN PT LC masih memakai versi terdampak.

4. KONDISI KONTROL KITA
  Jalur email           : celah. Lampiran skrip di dalam zip tidak diperiksa.
  Jalur VPN             : celah. Patch tersedia sejak 25 Sep, belum dipasang.
  Deteksi di laptop     : sebagian. Terdeteksi tetapi diberi prioritas rendah.
  Deteksi pencurian data: belum ada.
  Laptop tanpa EDR      : sekitar 900 unit, terutama di gudang.

5. REKOMENDASI
  1. Pasang patch VPN GateSecure di luar jadwal. Pemilik: Kepala Infrastruktur. Tenggat: 16 Okt.
  2. Blokir lampiran skrip (.js, .vbs, .hta) di dalam arsip. Pemilik: tim email. Tenggat: 14 Okt.
  3. Naikkan prioritas alert eksekusi skrip dari folder unduhan. Pemilik: SOC lead. Tenggat: 14 Okt.
  4. Jalankan tiga hunt yang sudah disiapkan (lampiran teknis). Pemilik: SOC/IR. Tenggat: 23 Okt.
  5. Percepat pemasangan EDR di laptop gudang. Pemilik: Kepala TI. Usulan anggaran: kuartal ini.

6. KETERBATASAN DAN APA YANG BISA MENGUBAH PENILAIAN
- Informasi tentang kelompok ini berasal dari dua laporan vendor dan satu laporan ISAC.
- Klaim di forum publik bahwa PT LC sudah dibobol tidak terverifikasi; temuan internal kami
  tidak mendukung klaim kebocoran data saat ini.
- Penilaian naik bila hunt menemukan aktivitas di host lain atau log VPN menunjukkan
  percobaan eksploitasi. Penilaian turun bila vendor melaporkan kampanye berhenti.

7. SUMBER
  Laporan vendor A, 8 Okt 2026 (B2) ; laporan vendor B, 2 Okt 2026 (B3) ;
  email ISAC logistik, 7 Okt 2026 (B2, TLP:GREEN) ; katalog kerentanan yang dieksploitasi (A1) ;
  data internal PT LC (A1). Tabel istilah kemungkinan terlampir.
Lampiran teknis: CTI-2026-044-L1 (TLP:AMBER+STRICT), untuk SOC/IR.
TLP:AMBER
```

Catatan desain brief:

- Fakta internal ditempatkan pertama karena itulah yang paling mengubah keputusan direksi; profil aktor menyusul.
- Klaim forum (bahan E) disebut, karena direksi mungkin sudah mendengarnya, tetapi diposisikan dengan jujur sebagai tidak terverifikasi.
- Klaim sponsor negara dari bahan B ditolak secara eksplisit dengan alasan, bukan diabaikan diam-diam.
- Setiap rekomendasi punya pemilik dan tenggat; direksi hanya diminta memutuskan dua hal.
- Tidak ada IOC dan ID ATT&CK di brief; semuanya di lampiran teknis dengan label lebih ketat, karena IOC dari ISAC hanya boleh dibagikan sebatas TLP:GREEN dan lampiran juga memuat detail kerentanan internal.

### 2.5 Pemetaan ke hipotesis hunting

Rekomendasi keempat di brief meminta SOC/IR menjalankan hunt dari lampiran teknis. Tabel ini menurunkan hipotesis dari tabel procedure di bagian 2.3; perhatikan kolom kriteria selesai, karena tanpa kolom itu hunt tidak pernah selesai.

| ID | TTP | Hipotesis | Data | Langkah | Kriteria selesai | Keluaran bila ditemukan |
|---|---|---|---|---|---|---|
| H1 | T1566.001, T1204.002 | Bila penerima lain membuka lampiran yang sama, maka ada wscript atau cscript menjalankan .js dari folder unduhan di host selain WS-021 sejak 1 Oktober | EDR, log proses | Cari eksekusi skrip dari folder unduhan; cocokkan dengan 11 penerima email | Terbukti bila ada host lain; tidak terbukti bila nihil di semua host ber-EDR; catat 30% host tanpa EDR sebagai celah | Isolasi host, rule prioritas tinggi |
| H2 | T1053.005 | Bila penyerang memasang persistence di host lain, maka ada scheduled task baru yang aksinya di ProgramData sejak 1 Oktober | EDR, Security 4698 di server | Daftar task baru, saring yang dibuat agen sah | Terbukti bila ada task tanpa penjelasan sah | Insiden, rule Sigma |
| H3 | T1071.001 | Bila ada implant aktif, maka ada host dengan koneksi HTTPS interval seragam ke domain berumur kurang dari 30 hari | Proxy, DNS, WHOIS | Hitung keseragaman interval per host-domain; buang tujuan sah | Terbukti bila ada pasangan tanpa penjelasan | Insiden, rule beaconing |
| H4 | T1190, T1133 | Bila VPN sudah dieksploitasi, maka ada pola permintaan tidak lazim ke appliance atau sesi VPN dari akun yang tidak biasa sejak 25 September | Log VPN, log autentikasi | Cari sesi baru dari lokasi atau jam tidak biasa; cek indikator dari advisori vendor GateSecure | Terbukti bila ada sesi tanpa penjelasan | IR untuk appliance, reset kredensial |
| H5 | T1567.002 | Bila data sudah dicuri, maka ada unggahan lebih dari 500 MB ke layanan cloud storage dari host yang biasanya tidak melakukannya | Proxy | Total byte keluar per host per kategori tujuan | Terbukti bila ada lonjakan tanpa penjelasan | Penilaian kebocoran data, pertimbangan kewajiban pelaporan |

Hasil fiktif setelah hunt dijalankan: H1 menemukan satu host lain (WS-033) yang menjalankan .js tetapi gagal menghubungi C2 karena terblokir proxy; H2-H5 tidak terbukti. Temuan H1 menjadi pembaruan brief singkat dan menaikkan prioritas rule eksekusi skrip.

## 3. Lab praktik

Lab ini menempatkanmu di posisi tim CTI PT LC yang menerima pesan CISO. Kerjakan tanpa melihat bagian 2 lebih dulu.

**Prasyarat:** editor teks dan bahan di bagian 1. Untuk versi ancaman nyata, akses baca ke laporan publik sah; jangan mengarang fakta tentang aktor nyata. IOC di-defang.

1. **Konsumen.** Tentukan konsumen dan jenis produk yang dibutuhkan, termasuk produk yang harus dikirim sebelum brief direksi.
2. **Nilai bahan.** Beri kode Admiralty untuk bahan A-F dengan alasan, dan tulis apa yang diambil dan tidak diambil dari tiap bahan.
3. **Fakta dan penilaian.** Dari bahan A dan B, pisahkan minimal sepuluh klaim menjadi fakta, penilaian, pemasaran, dan IOC.
4. **ACH.** Susun matriks ACH untuk pertanyaan tentang WS-021 dan tulis bukti apa yang paling membedakan hipotesis.
5. **Diamond dan ATT&CK.** Isi Diamond dan tabel procedure ke ATT&CK beserta telemetri dan status deteksi.
6. **Brief.** Isi template 3.1.
7. **Lampiran teknis.** Tulis lampiran teknis untuk SOC dengan TTP, IOC berkonteks, dan tindakan.
8. **Hunting.** Isi template 3.2 dengan minimal tiga hipotesis lengkap dengan kriteria selesai.
9. **Nilai diri.** Pakai rubrik 3.3, lalu bandingkan hasilmu dengan bagian 2.
10. **Rencana lanjut.** Isi rencana di bagian 3.4 berdasarkan skor rubrik.

**Hasil yang sebaiknya tersimpan:**

- Pesan cepat ke SOC/IR untuk temuan internal.
- Tabel penilaian bahan A-F.
- Matriks ACH dengan kesimpulan tentang bukti yang dibutuhkan.
- Diamond dan tabel procedure ke ATT&CK.
- Brief dua halaman dan lampiran teknis.
- Pemetaan minimal tiga hipotesis hunting.
- Skor rubrik, perbandingan dengan bagian 2, dan daftar Day yang perlu diulang.

**Variasi tantangan:** kerjakan ulang skenario dengan satu perubahan: bahan D tidak ada, sehingga PT LC belum punya indikasi internal. Tulis ulang BLUF dan rekomendasi, lalu jelaskan bagaimana kemungkinan, keyakinan, dan urgensi berubah. Variasi kedua: anggap bahan E disertai sampel data yang tampak seperti data karyawan PT LC; tulis langkah validasi dan siapa yang harus dilibatkan sebelum ada pernyataan apa pun.

### 3.1 Template brief dua halaman

Template ini mengikuti urutan brief di bagian 2.4: BLUF lebih dulu, lalu fakta, ancaman, relevansi, kondisi kontrol, rekomendasi, dan keterbatasan.

```
TLP:<LABEL>
<No. produk> | <tanggal> | <analis/tim> | Menjawab <PIR> | Keyakinan keseluruhan: <rendah/sedang/tinggi>

BRIEF ANCAMAN: <judul yang menyebut ancaman dan dampaknya>

BLUF (3-5 kalimat)
<apa> <jadi apa bagi organisasi ini> <seberapa yakin> <keputusan atau tindakan yang diminta>

1. APA YANG TERJADI / APA YANG KAMI AMATI
[Fakta] <observasi + sumber + Admiralty>
[Penilaian] <kesimpulan + kemungkinan + keyakinan>

2. SIAPA ANCAMANNYA
<nama utama + alias + catatan tumpang tindih> ; <motivasi [penilaian]> ; <pola korban>

3. KENAPA PENTING BAGI KITA
<kecocokan profil korban> ; <dampak yang dialami korban lain> ; <jalur masuk yang relevan>

4. KONDISI KONTROL KITA
<per jalur masuk/tahap: ada / sebagian / celah>

5. REKOMENDASI
<n>. <tindakan>. Pemilik: <...>. Tenggat: <...>.

6. KETERBATASAN DAN APA YANG BISA MENGUBAH PENILAIAN
<celah informasi> ; <klaim yang ditolak dan alasannya> ; <indikator naik/turun>

7. SUMBER
<sumber + tanggal + Admiralty> ; <lampiran teknis + label>
TLP:<LABEL>
```

### 3.2 Template pemetaan ke hipotesis hunting

Template ini sama dengan tabel di bagian 2.5; aturan di bawahnya yang membuat hipotesis bisa diuji.

```
| ID | TTP (ATT&CK) | Hipotesis (bila ... maka ...) | Data | Langkah | Kriteria selesai | Keluaran bila ditemukan |
|----|--------------|-------------------------------|------|---------|------------------|-------------------------|
| H1 |              |                               |      |         |                  |                         |

Aturan: satu hipotesis per procedure ; data harus benar-benar tersedia ; kriteria selesai
memuat terbukti / tidak terbukti / tidak bisa diuji ; temuan menjadi rule atau insiden.
```

### 3.3 Rubrik penilaian diri

Rubrik ini ada supaya kamu bisa menilai hasil sendiri dengan jujur dan menemukan Day yang perlu diulang; cari kriteria yang bernilai 0 atau 1. Beri nilai 0, 1, atau 2 untuk setiap kriteria. Total maksimal 24.

| Kriteria | 0 | 1 | 2 |
|---|---|---|---|
| Konsumen dan urgensi | Satu produk untuk semua; tidak melihat urgensi bahan D | Dua produk, tetapi temuan internal baru disampaikan di brief | Pesan cepat ke SOC/IR sebelum brief; brief dan lampiran terpisah |
| Penilaian sumber | Tanpa Admiralty | Admiralty ada, alasan tipis | Admiralty dengan alasan; bahan E dan klaim sponsor negara ditangani eksplisit |
| Fakta vs penilaian | Tercampur | Sebagian ditandai | Setiap klaim di brief jelas fakta atau penilaian |
| Bahasa estimatif | Kata kabur ("mungkin") | Istilah terdefinisi tanpa keyakinan | Kemungkinan dan keyakinan dinyatakan terpisah dan konsisten |
| ACH | Tidak dilakukan | Matriks ada, tetapi memaksa satu jawaban | Matriks menunjukkan bukti yang membedakan dan mengarah ke hunt |
| Bias | Tidak disebut | Disebut umum | Bias spesifik dikenali dan bukti penahan disebut |
| ATT&CK | Hanya nama tactic | Technique tanpa procedure | Procedure, technique, telemetri, dan status deteksi |
| BLUF | Kesimpulan di akhir | Ada BLUF tanpa tindakan | BLUF memuat apa, jadi apa, keyakinan, keputusan |
| Rekomendasi | Umum | Spesifik tanpa pemilik atau tenggat | Spesifik, pemilik, tenggat; keputusan direksi dibatasi |
| TLP | Tidak ada atau salah | Label ada, tidak diwariskan | Label benar, diwariskan, lampiran dipisah, penulisan sesuai aturan |
| Hipotesis hunting | Kabur | Spesifik tanpa kriteria selesai | Minimal tiga, dengan data, langkah, dan kriteria selesai |
| Keterbatasan | Tidak ada | Disebut umum | Celah spesifik dan indikator yang mengubah penilaian |

Cara membaca total: 20-24 berarti siap mengerjakan profil ancaman nyata; 14-19 berarti alurnya sudah ada, ulangi Day yang terkait kriteria bernilai 0 atau 1; di bawah 14 berarti ulangi Day 03, 09, dan 11 sebelum mencoba lagi.

Peta kriteria ke Day: penilaian sumber, ACH, dan bias ke Day 03; ATT&CK dan Diamond ke Day 04 dan 09; IOC ke Day 07; hunting ke Day 10; BLUF, bahasa estimatif, dan TLP ke Day 11; konsumen ke Day 01 dan 02.

### 3.4 Rencana lanjut

Skor rubrik baru berguna bila diterjemahkan menjadi latihan berikutnya. Setelah capstone, isi rencana lanjut berikut:

- **Kekuatan:** kriteria rubrik yang bernilai 2.
- **Kelemahan:** kriteria bernilai 0 atau 1 dan Day yang terkait.
- **Latihan berikutnya:** profilkan satu ancaman nyata yang relevan dengan sektor yang kamu kenal, memakai laporan publik sah, dengan template yang sama.
- **Integrasi:** muat IOC dan rule dari latihan ke SIEM lab dan jalankan satu hipotesis hunt dengan data lab.
- **Lanjutan di topik ini:** vulnerability intelligence (Day 13) untuk jalur masuk lewat kerentanan seperti bahan F, ekosistem kriminal (Day 14) untuk membaca klaim seperti bahan E, dan konteks pelaporan Indonesia (Day 16) untuk kewajiban yang muncul bila H5 terbukti.

## 4. Troubleshooting

Gejala berikut muncul saat mengerjakan lab di bagian 3; cari baris yang cocok dengan hasil yang terasa janggal.

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Brief selesai, tetapi temuan internal terlambat sampai ke SOC | Fokus pada produk, bukan pada urgensi | Kirim pesan cepat begitu ada indikasi internal |
| Brief terasa seperti ringkasan laporan vendor | Tidak ada hubungan ke kondisi organisasi | Tambahkan bagian kondisi kontrol dan kecocokan profil |
| ACH selalu memilih skenario terburuk | Bias konfirmasi dari laporan yang dibaca pertama | Cari bukti yang tidak konsisten dengan hipotesis favorit |
| Rekomendasi tidak dijalankan | Tanpa pemilik dan tenggat, atau terlalu banyak keputusan | Batasi keputusan pimpinan; sisanya ke pemilik operasional |
| Hipotesis hunt tidak bisa diuji | Data tidak tersedia | Catat sebagai celah telemetri dan ajukan perbaikan |
| Klaim tidak terverifikasi masuk brief sebagai fakta | Penilaian sumber dilewati | Nilai setiap bahan sebelum menulis |

## 5. Kesalahan umum dan jebakan

- **Menunggu brief selesai untuk menyampaikan temuan internal.** Indikasi kompromi harus sampai ke IR segera.
- **Memaksa atribusi.** Nama aktor tidak mengubah tindakan; jalur masuk dan kondisi kontrol yang mengubah.
- **Menerima atau mengabaikan klaim diam-diam.** Klaim yang ditolak perlu disebut beserta alasannya bila pembaca mungkin sudah mendengarnya.
- **Brief berisi IOC dan ID teknik.** Pindahkan ke lampiran teknis dengan label yang sesuai.
- **Rekomendasi tanpa pemilik.** Rekomendasi tanpa pemilik tidak akan dijalankan.
- **Hipotesis tanpa kriteria selesai.** Hunt tidak pernah selesai.
- **Menganggap alert yang ditutup sebagai fakta.** Status "benign" dari triage awal adalah penilaian yang bisa salah.

## 6. Catatan terkini

Bagian ini menampung versi standar yang dipakai skenario. Detail ini tidak mengubah alur kerja capstone, tetapi menentukan ID technique yang kamu tulis.

ATT&CK v19, TLP 2.0, dan STIX/TAXII 2.1 adalah versi yang dipakai di Day ini. ID technique di skenario sudah dipakai di Day 07-11; cek ulang bila kamu memakai versi ATT&CK yang lebih baru, terutama untuk tactic yang berubah di v19.

## 7. Cheat sheet

```
URUTAN     konsumen+urgensi -> nilai bahan (Admiralty) -> fakta/penilaian -> ACH -> Diamond + ATT&CK (procedure)
           -> kondisi kontrol -> brief + lampiran (TLP) -> hipotesis hunt -> rubrik
URGENSI    indikasi internal = pesan cepat ke SOC/IR SEKARANG, brief menyusul
BAHAN      vendor dgn metodologi > vendor tanpa metodologi ; ISAC dgn korban langsung ; data sendiri A1 ;
           forum anonim F6 = pemicu cek, bukan fakta
ACH        tujuan sering bukan memilih jawaban, tapi menemukan BUKTI PEMBEDA -> hunt
BRIEF 2H   TLP | BLUF | apa terjadi | siapa | kenapa penting | kondisi kontrol | rekomendasi (pemilik, tenggat) |
           keterbatasan + indikator | sumber | TLP
LAMPIRAN   TTP (procedure -> ATT&CK) + IOC (defang, keyakinan, expiry, PAP) + tindakan SOC ; label lebih ketat bila perlu
HUNT       ID | TTP | bila..maka | data | langkah | kriteria selesai | keluaran
RUBRIK     12 kriteria x 0-2 ; 20-24 siap ; 14-19 ulangi Day terkait ; <14 ulangi Day 03, 09, 11
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Alert EDR di WS-021 sudah ditutup analis SOC sebagai benign, dan pengguna bilang tidak terjadi apa-apa. Apakah bahan D cukup dicatat sebagai latar belakang di brief direksi?

<details><summary>Jawaban</summary>

Tidak. Status "benign" dari triage awal adalah penilaian yang belum diuji, bukan fakta. Alert eksekusi .js dari folder unduhan, ditambah query DNS ke domain dari laporan vendor A, adalah indikasi bahwa procedure akses awal kampanye sudah terjadi di PT LC. Langkah yang tepat adalah berhenti sebentar dari menulis brief dan mengirim pesan singkat ke SOC lead dan IR (TLP:AMBER+STRICT) agar WS-021 diperiksa ulang hari itu juga; brief menyusul. Lihat bagian 2.1 dan 5.

</details>

**2. Skenario keputusan.** Bahan E, unggahan akun anonim di forum publik, mengklaim PT LC sudah dibobol. Direksi mungkin sudah mendengarnya. Apa yang paling tepat?

- A. Masukkan ke brief sebagai fakta supaya direksi waspada.
- B. Abaikan diam-diam karena sumbernya anonim.
- C. Beri kode F6, pakai hanya sebagai pemicu pemeriksaan, lalu sebut di brief sebagai klaim tidak terverifikasi dan bandingkan dengan temuan internal.

<details><summary>Jawaban</summary>

C. Akun anonim tanpa bukti tidak bisa dinilai keandalan maupun kredibilitasnya, jadi kodenya F6, dan satu-satunya yang diambil adalah dorongan untuk memeriksa. Karena direksi mungkin sudah mendengarnya, brief menyebutnya di bagian keterbatasan: tidak terverifikasi, dan temuan internal tidak mendukung klaim kebocoran data saat ini. A keliru karena klaim tak terverifikasi masuk brief sebagai fakta adalah tanda penilaian sumber dilewati. B keliru karena klaim yang ditolak perlu disebut beserta alasannya bila pembaca mungkin sudah mendengarnya. Lihat bagian 2.1, 2.4, dan 5.

</details>

**3. Pertanyaan jebakan.** "Matriks ACH untuk WS-021 gagal karena tidak menghasilkan satu hipotesis pemenang." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Matriks itu berhasil menggugurkan H4 (aktivitas tidak terkait kampanye) karena tiga bukti tidak konsisten, dan menunjukkan bahwa H1, H2, dan H3 belum bisa dibedakan dengan bukti yang ada. Hasil yang berguna adalah daftar bukti pembeda yang belum dikumpulkan: scheduled task baru di WS-021, koneksi HTTPS periodik ke tujuan lain, dan unggahan besar. Itu yang diteruskan menjadi hunt. Matriks juga membantu menahan bias: ketiadaan koneksi ke IP C2 adalah bukti yang menahan kesimpulan skenario terburuk (H2). Lihat bagian 2.2.

</details>

**4. Skenario keputusan.** Brief untuk direksi berlabel TLP:AMBER. Di mana IOC dan ID ATT&CK ditempatkan?

- A. Di badan brief, supaya direksi melihat bahwa analisisnya lengkap.
- B. Di lampiran teknis terpisah berlabel TLP:AMBER+STRICT untuk SOC/IR.
- C. Di lampiran teknis berlabel TLP:CLEAR, karena laporan vendor A dan B berlabel TLP:CLEAR.

<details><summary>Jawaban</summary>

B. Direksi tidak butuh IOC dan ID teknik untuk dua keputusan yang diminta, sedangkan SOC/IR butuh semuanya untuk bertindak, jadi isinya dipisah ke lampiran teknis. A keliru karena brief berisi IOC dan ID teknik adalah kesalahan umum yang membuat produk strategic sulit dibaca. C keliru karena lampiran juga memuat IOC dari ISAC (bahan C, TLP:GREEN) dan detail kerentanan internal PT LC; label harus menghormati label sumber dan isi internalnya, bukan mengikuti bahan yang paling longgar. Lihat bagian 2.4 dan 5.

</details>

**5. Jelaskan ulang.** Seorang direktur bertanya, "Jadi siapa pelakunya, FICTA SPIDER atau Storm-0000? Dan benarkah mereka didukung negara?" Jawab dalam tiga sampai empat kalimat.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Itu dua nama yang dipakai dua vendor keamanan untuk kelompok kriminal yang cakupannya tumpang tindih sebagian, dan kami tidak perlu memilih salah satunya untuk bertindak. Kami menilai hampir pasti kelompok ini bermotif uang, dengan keyakinan tinggi, karena polanya mencuri data lalu mengenkripsi dan memeras korban. Klaim dukungan negara datang dari satu laporan tanpa metodologi dan tanpa dasar yang dijelaskan, jadi tidak kami dukung. Yang menentukan tindakan kita adalah jalur masuknya, yaitu lampiran email dan celah VPN yang belum ditambal, bukan namanya."

Kesalahan yang sering muncul:
- Memilih satu nama sebagai "pelaku sebenarnya", yang berarti atribusi pasti tanpa dasar.
- Mengulang klaim sponsor negara tanpa menyebut bahwa dasarnya tidak dijelaskan.
- Menjawab panjang tentang aktor tanpa kembali ke keputusan yang diminta (patch VPN dan blokir lampiran skrip).
- Mencampur kemungkinan dan keyakinan dalam satu kata kabur seperti "mungkin".

</details>

**6. Skenario keputusan.** Mana hipotesis hunting yang siap diuji di PT LC?

- A. "Cari aktivitas LOGI-FICTA di jaringan."
- B. "Bila penyerang memasang persistence di host lain, maka ada scheduled task baru yang aksinya di ProgramData sejak 1 Oktober." Data: EDR dan Security 4698 di server. Terbukti bila ada task tanpa penjelasan sah.
- C. "Bila ada implant di laptop gudang, maka EDR di laptop gudang menunjukkan proses mencurigakan."

<details><summary>Jawaban</summary>

B. Hipotesis itu berbentuk "bila ... maka ...", terikat satu procedure, memakai data yang benar-benar tersedia, dan punya kriteria selesai. A keliru karena tidak ada hipotesis, data, atau kriteria selesai, sehingga hunt tidak pernah selesai. C keliru karena sekitar 30 persen endpoint yang belum terpasang EDR adalah laptop gudang lama, jadi datanya tidak tersedia; kondisi seperti itu dicatat sebagai celah telemetri dan diajukan perbaikannya, bukan dijadikan hunt. Lihat bagian 1.1, 2.5, 3.2, dan 4.

</details>

**7. Interview question (English).** "Your CISO forwards a news article about ransomware hitting another company in our sector and asks whether it's relevant to us. How do you approach it?"

<details><summary>Sample answer</summary>

"I start by turning the request into a clear requirement: which ransomware threats are likely to target us, through which entry points, and whether our current controls would detect or stop them. Then I collect and grade the sources, separating facts from assessments, marketing language and unverified claims like anonymous forum posts. The most important step is checking our own telemetry against what the reports describe, because an alert that was closed as benign might actually be the campaign's initial access. If I see any sign of compromise, I message the SOC and IR straight away instead of waiting for the brief. After that I map the procedures to ATT&CK together with our telemetry and detection status, write a two-page brief with a bottom line up front, a TLP label and recommendations that each have an owner and a deadline, and put the IOCs and technique IDs in a separate technical annex. Finally, I turn the gaps into testable hunting hypotheses with clear completion criteria."

What makes this answer strong: it starts from the requirement rather than the article, grades sources before using them, connects external intelligence with internal data, puts urgency ahead of polish, separates products by consumer and TLP, and ends in owned actions and hunts.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | CTI-note Day 01-11 | (lokal) | rujukan internal | 2026-10-10 | Seluruh konsep yang dipadukan |
| S2 | MITRE ATT&CK | https://attack.mitre.org/ | primer | diakses 2026-10-09 | Tinggi. Technique yang dipakai di skenario |
| S3 | FIRST: Traffic Light Protocol (TLP) 2.0 | https://www.first.org/tlp/ | primer | diakses 2026-10-09 | Tinggi. Label produk |
| S4 | Caltagirone, Pendergast, Betz: The Diamond Model of Intrusion Analysis (2013) | https://www.activeresponse.org/the-diamond-model/ | primer | diakses 2026-10-09 | Tinggi. Kerangka empat sudut |
| S5 | ODNI: Intelligence Community Directive 203, Analytic Standards | https://www.dni.gov/files/documents/ICD/ICD-203.pdf | primer | diakses 2026-10-09 | Tinggi. Bahasa estimatif |

**Catatan sumber:** capstone tidak menambah klaim teknis baru; konsepnya bersandar pada Day 01-11 dan sumbernya. Seluruh skenario, bahan, hasil hunt, dan produk di bagian 1-2 fiktif. Ambang di rubrik dan batas skor adalah susunan sendiri untuk latihan, bukan standar penilaian dari lembaga mana pun.
