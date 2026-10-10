---
day: 12
title: 'Capstone CTI: memprofilkan satu ancaman end-to-end, template brief dua halaman, dan pemetaan ke hipotesis hunting'
researched_on: 2026-10-10
versions_checked: 'MITRE ATT&CK v19; FIRST TLP 2.0; STIX/TAXII 2.1; rujukan Day 01-11'
---

# Day 12: Capstone CTI

Cakupan: satu latihan terpadu dengan skenario fiktif lengkap, dari PIR dan bahan mentah sampai brief dua halaman, pemetaan ke hipotesis hunting, contoh produk akhir yang bisa dicontoh, dan rubrik untuk menilai hasil kerjamu sendiri.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- memprofilkan satu ancaman dari PIR sampai produk yang bisa ditindaklanjuti, memakai bahan yang campur aduk kualitasnya.
- menilai setiap bahan dengan Admiralty dan memisahkan fakta, penilaian, dan klaim yang tidak bisa diverifikasi.
- memakai ACH untuk satu pertanyaan analitis yang benar-benar terbuka.
- memetakan ancaman ke Diamond Model dan ATT&CK pada tingkat procedure.
- menulis brief dua halaman ber-BLUF dan ber-TLP untuk dua konsumen.
- menurunkan minimal tiga hipotesis hunting yang bisa diuji.
- menilai hasil kerjamu dengan rubrik dan menentukan Day yang perlu diulang.

## 2. Konteks singkat

Capstone menguji apakah Day 01-11 sudah menyatu menjadi kemampuan menghasilkan intelijen yang berguna di bawah kondisi yang mirip pekerjaan nyata: bahan datang dari banyak sumber, keandalannya berbeda-beda, ada informasi internal yang belum jelas artinya, dan ada tenggat. Tidak ada materi baru. Yang dilatih adalah urutan kerja dan disiplin: kapan berhenti mengumpulkan, bagaimana menimbang bukti, dan bagaimana menulis sesuatu yang membuat orang lain bertindak.

Day ini memberi skenario fiktif lengkap dengan bahan mentahnya (bagian 3), contoh pengerjaan langkah demi langkah dan produk akhir (bagian 4), lalu lab dengan template dan rubrik penilaian diri (bagian 5). Cara terbaik memakainya: kerjakan bagian 5 lebih dulu dengan bahan di bagian 3, baru bandingkan hasilmu dengan bagian 4.

**Kapan dipakai:** menguji kesiapan; kerangka untuk profil ancaman nyata; contoh portofolio.

**Kapan terbatas:** skenario fiktif lebih rapi daripada kenyataan. Profil ancaman nyata butuh lebih banyak sumber dan atribusi yang lebih hati-hati.

## 3. Skenario latihan

Seluruh organisasi, orang, aktor, domain, IP, nomor CVE, dan angka di bagian ini fiktif. IOC di-defang.

### 3.1 Organisasi

PT Nusantara Logistik Fiktif (NLF) adalah perusahaan logistik dengan sekitar 3.000 karyawan, gudang di Jakarta, Surabaya, dan Medan, dan sistem manajemen gudang (WMS) on-premise yang menjadi tulang punggung operasi. Akses jarak jauh karyawan lewat appliance VPN merek fiktif "GateSecure". EDR terpasang di sekitar 70 persen endpoint; sisanya laptop gudang lama. SIEM menerima log email gateway, proxy, DNS, VPN, dan log Windows dari server.

Tim CTI terdiri dari dua orang dan melapor ke CISO. Konsumen produk CTI: CISO dan direksi (strategis), SOC lead dan IR (taktis), dan tim infrastruktur (patching).

### 3.2 PIR dan tenggat

PIR-02 yang disetujui CISO: "Ancaman ransomware mana yang kemungkinan menargetkan NLF dalam enam bulan ke depan, lewat jalur masuk apa, dan apakah kontrol kita saat ini cukup untuk mendeteksi atau mencegahnya?"

Pemicu: pada Jumat, 9 Oktober 2026, CISO meminta brief untuk rapat direksi Selasa depan, setelah membaca berita tentang serangan ransomware ke perusahaan logistik lain.

### 3.3 Bahan mentah

**Bahan A: laporan vendor A (TLP:CLEAR, terbit 8 Oktober 2026).** Laporan riset tentang kampanye yang mereka sebut "FICTA SPIDER". Isinya: enam korban perusahaan logistik di Indonesia, Malaysia, dan Thailand antara Juli dan Oktober 2026; akses awal lewat email bertema faktur dengan lampiran zip berisi berkas .js; berkas dijalankan wscript; persistence lewat scheduled task dari ProgramData; komunikasi HTTPS dengan interval seragam; data diunggah ke layanan cloud storage dengan rclone; lalu enkripsi berkas di share jaringan dan penghapusan shadow copy. IOC: bad-logistics[.]example, invoice-check[.]example, 203.0.113[.]50. Metodologi: telemetri EDR dari enam pelanggan. Laporan dibuka dengan kalimat "salah satu kelompok paling berbahaya di kawasan".

**Bahan B: laporan vendor B (TLP:CLEAR, terbit 2 Oktober 2026).** Laporan tentang "Storm-0000". Isinya: korban di logistik dan ritel; dua jalur masuk, yaitu email dengan lampiran .js dalam zip dan eksploitasi kerentanan CVE-2026-99999 pada appliance VPN GateSecure; dua keluarga ransomware, salah satunya sama dengan bahan A. Laporan menyebut "kemungkinan didukung negara" tanpa menjelaskan dasarnya. Tidak ada metodologi.

**Bahan C: email ISAC logistik (TLP:GREEN, 7 Oktober 2026).** Dua anggota ISAC melaporkan menerima email berlampiran zip berisi .js bertema faktur dalam seminggu terakhir. Satu anggota menyebut satu host terinfeksi dan sudah diisolasi. Pengirim email memakai domain invoice-check[.]example.

**Bahan D: data internal NLF (internal).**

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

**Bahan E: unggahan di forum publik (tidak terverifikasi).** Akun anonim di forum publik mengklaim "LOGI-FICTA sudah masuk ke tiga perusahaan logistik besar di Jakarta, salah satunya NLF". Tidak ada bukti yang dilampirkan.

**Bahan F: katalog kerentanan yang dieksploitasi.** CVE-2026-99999 (GateSecure) masuk katalog kerentanan yang terbukti dieksploitasi pada 30 September 2026. Vendor GateSecure menerbitkan patch pada 25 September.

## 4. Contoh pengerjaan dan produk akhir

Bagian ini adalah satu contoh jawaban. Jawabanmu boleh berbeda selama alasannya jelas dan jujur tentang keyakinan.

### 4.1 Menilai bahan

| Bahan | Admiralty | Alasan | Yang diambil | Yang tidak diambil |
|---|---|---|---|---|
| A | B2 | Vendor dengan rekam jejak, data telemetri sendiri, konsisten dengan C | Procedure, korban, IOC | Superlatif pembuka |
| B | B3 | Vendor dikenal, tetapi tanpa metodologi; klaim sponsor negara tanpa dasar | Jalur masuk VPN, CVE, overlap ransomware | Klaim sponsor negara |
| C | B2 | ISAC dengan anggota langsung terdampak; isi cocok dengan A | Konfirmasi kampanye aktif, domain pengirim | Tidak ada |
| D | A1 | Data sendiri, bisa diperiksa ulang | Fakta email, eksekusi .js, query DNS | Kesimpulan "benign" analis SOC (belum diuji) |
| E | F6 | Akun anonim, tidak ada bukti, tidak bisa dinilai | Tidak ada, kecuali sebagai pemicu pemeriksaan | Klaim bahwa NLF sudah dibobol |
| F | A1 | Katalog resmi berbasis bukti eksploitasi | Status dieksploitasi, tanggal | Tidak ada |

Hal pertama yang terlihat setelah penilaian: bahan D jauh lebih penting daripada yang disadari. Alert EDR yang ditutup sebagai benign, ditambah query DNS ke domain dari laporan A, adalah indikasi bahwa procedure akses awal kampanye ini sudah terjadi di NLF. Brief untuk direksi tidak boleh menunggu; SOC dan IR harus diberi tahu hari itu juga.

Keputusan analis yang baik di titik ini: berhenti sebentar dari menulis brief dan menulis pesan singkat ke SOC lead dan IR (TLP:AMBER+STRICT) yang meminta WS-021 diperiksa ulang. Ini contoh CTI yang paling bernilai: menghubungkan intelijen eksternal dengan data internal yang sudah ada tetapi belum dibaca dengan konteks.

### 4.2 Pertanyaan analitis dan ACH

Pertanyaan terbuka: apa yang terjadi di WS-021 pada 7 Oktober?

| Bukti | H1: infeksi LOGI-FICTA, berhenti di tahap awal | H2: infeksi LOGI-FICTA, berlanjut tanpa terlihat | H3: berkas dijalankan tetapi gagal (terblokir atau rusak) | H4: aktivitas tidak terkait kampanye |
|---|---|---|---|---|
| Email dari domain yang disebut C | K | K | K | TK |
| wscript menjalankan .js dari Downloads | K | K | K | TK |
| Query DNS ke domain C2 dari laporan A | K | K | N | TK |
| Tidak ada koneksi proxy ke IP C2 | K | N | K | N |
| Tidak ada alert EDR lanjutan | K | N | K | N |
| EDR hanya mencatat eksekusi, tanpa event scheduled task (cek belum dilakukan) | N | N | N | N |

K = konsisten, TK = tidak konsisten, N = netral atau tidak membedakan.

Cara membaca: H4 gugur karena tiga bukti tidak konsisten. H1, H2, dan H3 tidak bisa dibedakan dengan bukti yang ada. Bukti yang paling membedakan belum dikumpulkan: apakah ada scheduled task baru di WS-021, apakah ada koneksi HTTPS periodik ke tujuan lain, dan apakah ada unggahan besar. Kesimpulan ACH di sini bukan memilih hipotesis, melainkan menentukan bukti apa yang harus dicari. Itulah alasan hunt H1 dan H2 di bagian 4.5.

Satu catatan bias: setelah membaca laporan A, mudah melihat semua bukti sebagai konfirmasi H2 (skenario terburuk). Ketiadaan koneksi ke IP C2 justru bukti yang menahan kesimpulan itu.

### 4.3 Diamond dan ATT&CK

```
Diamond (kampanye LOGI-FICTA, sudut pandang NLF)
  Adversary     : cluster FICTA SPIDER (vendor A) / tumpang tindih sebagian dengan Storm-0000 (vendor B)
                  motivasi finansial [kemungkinan besar, keyakinan tinggi]
  Capability    : ransomware-lab ; .js dropper ; rclone ; scheduled task
  Infrastructure: domain bertema faktur/logistik baru didaftarkan ; VPS ; layanan cloud storage
  Victim        : logistik ID/MY/TH ; divisi keuangan sebagai penerima email ; WMS sebagai sasaran dampak
```

| Tahap | Procedure | ATT&CK | Telemetri NLF | Status deteksi NLF |
|---|---|---|---|---|
| Akses awal | Zip berisi .js bertema faktur | T1566.001 | Gateway email | Tidak ada (zip tidak diperiksa) |
| Akses awal (alternatif, bahan B) | Eksploitasi CVE-2026-99999 di VPN | T1190, lalu T1133 | Log VPN | Tidak ada; patch belum dipasang |
| Eksekusi | wscript menjalankan .js dari Downloads | T1204.002, T1059.007 | EDR (70% endpoint) | Ada, severity rendah, ditutup sebagai benign |
| Persistence | Scheduled task dari ProgramData | T1053.005 | EDR, Security 4698 di server | Sebagian |
| C2 | HTTPS interval seragam | T1071.001 | Proxy, DNS | Tidak ada |
| Exfiltration | rclone ke cloud storage | T1567.002 | Proxy | Tidak ada |
| Impact | Hapus shadow copy, enkripsi share | T1490, T1486 | EDR, log server | Ada untuk T1490; belum teruji |

### 4.4 Produk akhir: brief dua halaman

Brief ini ditulis Senin, 12 Oktober 2026, setelah SOC memeriksa ulang WS-021 dan menemukan scheduled task mencurigakan yang kemudian dihapus dan host di-reimage. Brief menggabungkan bahan A-F dengan hasil pemeriksaan itu.

```
TLP:AMBER
CTI-2026-044 | 12 Oktober 2026 | Tim CTI NLF | Menjawab PIR-02 | Keyakinan keseluruhan: SEDANG

BRIEF ANCAMAN: KAMPANYE RANSOMWARE LOGI-FICTA TERHADAP SEKTOR LOGISTIK

BLUF
NLF sudah menjadi sasaran kampanye ransomware LOGI-FICTA: pada 7 Oktober satu laptop
divisi keuangan terinfeksi lewat lampiran email, dan infeksi itu dihentikan pada
10 Oktober sebelum ada tanda pencurian data atau enkripsi. Kami menilai sangat mungkin
(keyakinan sedang) kampanye ini akan mencoba lagi dalam tiga bulan ke depan, lewat email
yang sama atau lewat celah pada VPN kita yang belum ditambal. Kami meminta dua keputusan
minggu ini: pemasangan patch VPN di luar jadwal pemeliharaan, dan pemblokiran lampiran
skrip di dalam arsip email.

1. APA YANG TERJADI DI NLF
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

3. KENAPA PENTING BAGI NLF
- Profil korban (logistik, kawasan ini, sistem gudang) cocok dengan NLF.
- Korban lain melaporkan gangguan operasional gudang lebih dari satu minggu [sumber B2].
- Jalur masuk kedua, celah pada appliance VPN GateSecure, sudah terbukti dieksploitasi
  sejak akhir September [sumber A1]. VPN NLF masih memakai versi terdampak.

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
- Klaim di forum publik bahwa NLF sudah dibobol tidak terverifikasi; temuan internal kami
  tidak mendukung klaim kebocoran data saat ini.
- Penilaian naik bila hunt menemukan aktivitas di host lain atau log VPN menunjukkan
  percobaan eksploitasi. Penilaian turun bila vendor melaporkan kampanye berhenti.

7. SUMBER
  Laporan vendor A, 8 Okt 2026 (B2) ; laporan vendor B, 2 Okt 2026 (B3) ;
  email ISAC logistik, 7 Okt 2026 (B2, TLP:GREEN) ; katalog kerentanan yang dieksploitasi (A1) ;
  data internal NLF (A1). Tabel istilah kemungkinan terlampir.
Lampiran teknis: CTI-2026-044-L1 (TLP:AMBER+STRICT), untuk SOC/IR.
TLP:AMBER
```

Catatan desain brief:

- Fakta internal ditempatkan pertama karena itulah yang paling mengubah keputusan direksi; profil aktor menyusul.
- Klaim forum (bahan E) disebut, karena direksi mungkin sudah mendengarnya, tetapi diposisikan dengan jujur sebagai tidak terverifikasi.
- Klaim sponsor negara dari bahan B ditolak secara eksplisit dengan alasan, bukan diabaikan diam-diam.
- Setiap rekomendasi punya pemilik dan tenggat; direksi hanya diminta memutuskan dua hal.
- Tidak ada IOC dan ID ATT&CK di brief; semuanya di lampiran teknis dengan label lebih ketat, karena IOC dari ISAC hanya boleh dibagikan sebatas TLP:GREEN dan lampiran juga memuat detail kerentanan internal.

### 4.5 Pemetaan ke hipotesis hunting

| ID | TTP | Hipotesis | Data | Langkah | Kriteria selesai | Keluaran bila ditemukan |
|---|---|---|---|---|---|---|
| H1 | T1566.001, T1204.002 | Bila penerima lain membuka lampiran yang sama, maka ada wscript atau cscript menjalankan .js dari folder unduhan di host selain WS-021 sejak 1 Oktober | EDR, log proses | Cari eksekusi skrip dari folder unduhan; cocokkan dengan 11 penerima email | Terbukti bila ada host lain; tidak terbukti bila nihil di semua host ber-EDR; catat 30% host tanpa EDR sebagai celah | Isolasi host, rule prioritas tinggi |
| H2 | T1053.005 | Bila penyerang memasang persistence di host lain, maka ada scheduled task baru yang aksinya di ProgramData sejak 1 Oktober | EDR, Security 4698 di server | Daftar task baru, saring yang dibuat agen sah | Terbukti bila ada task tanpa penjelasan sah | Insiden, rule Sigma |
| H3 | T1071.001 | Bila ada implant aktif, maka ada host dengan koneksi HTTPS interval seragam ke domain berumur kurang dari 30 hari | Proxy, DNS, WHOIS | Hitung keseragaman interval per host-domain; buang tujuan sah | Terbukti bila ada pasangan tanpa penjelasan | Insiden, rule beaconing |
| H4 | T1190, T1133 | Bila VPN sudah dieksploitasi, maka ada pola permintaan tidak lazim ke appliance atau sesi VPN dari akun yang tidak biasa sejak 25 September | Log VPN, log autentikasi | Cari sesi baru dari lokasi atau jam tidak biasa; cek indikator dari advisori vendor GateSecure | Terbukti bila ada sesi tanpa penjelasan | IR untuk appliance, reset kredensial |
| H5 | T1567.002 | Bila data sudah dicuri, maka ada unggahan lebih dari 500 MB ke layanan cloud storage dari host yang biasanya tidak melakukannya | Proxy | Total byte keluar per host per kategori tujuan | Terbukti bila ada lonjakan tanpa penjelasan | Penilaian kebocoran data, pertimbangan kewajiban pelaporan |

Hasil fiktif setelah hunt dijalankan: H1 menemukan satu host lain (WS-033) yang menjalankan .js tetapi gagal menghubungi C2 karena terblokir proxy; H2-H5 tidak terbukti. Temuan H1 menjadi pembaruan brief singkat dan menaikkan prioritas rule eksekusi skrip.

## 5. Lab praktik

**Prasyarat:** editor teks dan bahan di bagian 3. Untuk versi ancaman nyata, akses baca ke laporan publik sah; jangan mengarang fakta tentang aktor nyata. IOC di-defang.

Kerjakan tanpa melihat bagian 4 lebih dulu.

1. **Konsumen.** Tentukan konsumen dan jenis produk yang dibutuhkan, termasuk produk yang harus dikirim sebelum brief direksi.
2. **Nilai bahan.** Beri kode Admiralty untuk bahan A-F dengan alasan, dan tulis apa yang diambil dan tidak diambil dari tiap bahan.
3. **Fakta dan penilaian.** Dari bahan A dan B, pisahkan minimal sepuluh klaim menjadi fakta, penilaian, pemasaran, dan IOC.
4. **ACH.** Susun matriks ACH untuk pertanyaan tentang WS-021 dan tulis bukti apa yang paling membedakan hipotesis.
5. **Diamond dan ATT&CK.** Isi Diamond dan tabel procedure ke ATT&CK beserta telemetri dan status deteksi.
6. **Brief.** Isi template 5.1.
7. **Lampiran teknis.** Tulis lampiran teknis untuk SOC dengan TTP, IOC berkonteks, dan tindakan.
8. **Hunting.** Isi template 5.2 dengan minimal tiga hipotesis lengkap dengan kriteria selesai.
9. **Nilai diri.** Pakai rubrik 5.3, lalu bandingkan hasilmu dengan bagian 4.

### 5.1 Template brief dua halaman

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

### 5.2 Template pemetaan ke hipotesis hunting

```
| ID | TTP (ATT&CK) | Hipotesis (bila ... maka ...) | Data | Langkah | Kriteria selesai | Keluaran bila ditemukan |
|----|--------------|-------------------------------|------|---------|------------------|-------------------------|
| H1 |              |                               |      |         |                  |                         |

Aturan: satu hipotesis per procedure ; data harus benar-benar tersedia ; kriteria selesai
memuat terbukti / tidak terbukti / tidak bisa diuji ; temuan menjadi rule atau insiden.
```

### 5.3 Rubrik penilaian diri

Beri nilai 0, 1, atau 2 untuk setiap kriteria. Total maksimal 24.

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

**Hasil yang sebaiknya tersimpan:**

- Pesan cepat ke SOC/IR untuk temuan internal.
- Tabel penilaian bahan A-F.
- Matriks ACH dengan kesimpulan tentang bukti yang dibutuhkan.
- Diamond dan tabel procedure ke ATT&CK.
- Brief dua halaman dan lampiran teknis.
- Pemetaan minimal tiga hipotesis hunting.
- Skor rubrik, perbandingan dengan bagian 4, dan daftar Day yang perlu diulang.

**Variasi tantangan:** kerjakan ulang skenario dengan satu perubahan: bahan D tidak ada, sehingga NLF belum punya indikasi internal. Tulis ulang BLUF dan rekomendasi, lalu jelaskan bagaimana kemungkinan, keyakinan, dan urgensi berubah. Variasi kedua: anggap bahan E disertai sampel data yang tampak seperti data karyawan NLF; tulis langkah validasi dan siapa yang harus dilibatkan sebelum ada pernyataan apa pun.

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Brief selesai, tetapi temuan internal terlambat sampai ke SOC | Fokus pada produk, bukan pada urgensi | Kirim pesan cepat begitu ada indikasi internal |
| Brief terasa seperti ringkasan laporan vendor | Tidak ada hubungan ke kondisi organisasi | Tambahkan bagian kondisi kontrol dan kecocokan profil |
| ACH selalu memilih skenario terburuk | Bias konfirmasi dari laporan yang dibaca pertama | Cari bukti yang tidak konsisten dengan hipotesis favorit |
| Rekomendasi tidak dijalankan | Tanpa pemilik dan tenggat, atau terlalu banyak keputusan | Batasi keputusan pimpinan; sisanya ke pemilik operasional |
| Hipotesis hunt tidak bisa diuji | Data tidak tersedia | Catat sebagai celah telemetri dan ajukan perbaikan |
| Klaim tidak terverifikasi masuk brief sebagai fakta | Penilaian sumber dilewati | Nilai setiap bahan sebelum menulis |

## 7. Kesalahan umum dan jebakan

- **Menunggu brief selesai untuk menyampaikan temuan internal.** Indikasi kompromi harus sampai ke IR segera.
- **Memaksa atribusi.** Nama aktor tidak mengubah tindakan; jalur masuk dan kondisi kontrol yang mengubah.
- **Menerima atau mengabaikan klaim diam-diam.** Klaim yang ditolak perlu disebut beserta alasannya bila pembaca mungkin sudah mendengarnya.
- **Brief berisi IOC dan ID teknik.** Pindahkan ke lampiran teknis dengan label yang sesuai.
- **Rekomendasi tanpa pemilik.** Rekomendasi tanpa pemilik tidak akan dijalankan.
- **Hipotesis tanpa kriteria selesai.** Hunt tidak pernah selesai.
- **Menganggap alert yang ditutup sebagai fakta.** Status "benign" dari triage awal adalah penilaian yang bisa salah.

## 8. Catatan terkini dan rencana lanjut

ATT&CK v19, TLP 2.0, dan STIX/TAXII 2.1 adalah versi yang dipakai di Day ini. ID technique di skenario sudah dipakai di Day 07-11; cek ulang bila kamu memakai versi ATT&CK yang lebih baru, terutama untuk tactic yang berubah di v19.

Setelah capstone, isi rencana lanjut berikut:

- **Kekuatan:** kriteria rubrik yang bernilai 2.
- **Kelemahan:** kriteria bernilai 0 atau 1 dan Day yang terkait.
- **Latihan berikutnya:** profilkan satu ancaman nyata yang relevan dengan sektor yang kamu kenal, memakai laporan publik sah, dengan template yang sama.
- **Integrasi:** muat IOC dan rule dari latihan ke SIEM lab dan jalankan satu hipotesis hunt dengan data lab.
- **Lanjutan di topik ini:** vulnerability intelligence (Day 13) untuk jalur masuk lewat kerentanan seperti bahan F, ekosistem kriminal (Day 14) untuk membaca klaim seperti bahan E, dan konteks pelaporan Indonesia (Day 16) untuk kewajiban yang muncul bila H5 terbukti.

## 9. Cheat sheet

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

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | CTI-note Day 01-11 | (lokal) | rujukan internal | 2026-10-10 | Seluruh konsep yang dipadukan |
| S2 | MITRE ATT&CK | https://attack.mitre.org/ | primer | diakses 2026-10-09 | Tinggi. Technique yang dipakai di skenario |
| S3 | FIRST: Traffic Light Protocol (TLP) 2.0 | https://www.first.org/tlp/ | primer | diakses 2026-10-09 | Tinggi. Label produk |
| S4 | Caltagirone, Pendergast, Betz: The Diamond Model of Intrusion Analysis (2013) | https://www.activeresponse.org/the-diamond-model/ | primer | diakses 2026-10-09 | Tinggi. Kerangka empat sudut |
| S5 | ODNI: Intelligence Community Directive 203, Analytic Standards | https://www.dni.gov/files/documents/ICD/ICD-203.pdf | primer | diakses 2026-10-09 | Tinggi. Bahasa estimatif |

**Catatan sumber:** capstone tidak menambah klaim teknis baru; konsepnya bersandar pada Day 01-11 dan sumbernya. Seluruh skenario, bahan, hasil hunt, dan produk di bagian 3-4 fiktif. Ambang di rubrik dan batas skor adalah susunan sendiri untuk latihan, bukan standar penilaian dari lembaga mana pun.
