---
day: 01
title: 'Gambaran CTI: tingkat intelijen, konsumen, dan bedanya dengan hunting dan IR'
researched_on: 2026-10-10
versions_checked: 'MWR InfoSecurity/CPNI/CERT-UK "Threat Intelligence: Collecting, Analysing, Evaluating" (2015); SANS 2026 CTI Survey (rilis pers 19 Mei 2026); TaHiTI whitepaper (versi di-host 2026-03); Flashpoint "Three types of threat intelligence" (Sep 2025, diperbarui Apr 2026)'
---

# Day 01: Gambaran CTI (tingkat, konsumen, dan bedanya dengan hunting dan IR)

Cakupan: definisi kerja CTI sebagai informasi untuk keputusan, empat tipe intelijen menurut konsumen beserta ketidakkonsistenan istilahnya, hubungan CTI dengan hunting dan IR, serta cara memecah satu laporan ancaman menjadi produk untuk beberapa konsumen.

## Ide inti

Threat intelligence adalah informasi yang membantu seseorang mengambil keputusan: apa yang diblokir hari ini, teknik apa yang dideteksi bulan ini, risiko apa yang dianggarkan tahun ini. Karena keputusannya berbeda-beda, konsumennya juga berbeda: direksi, CISO, detection engineer, dan analyst SOC masing-masing butuh bagian yang berbeda dari laporan yang sama. Feed IOC yang masuk ke SIEM memang bagian dari CTI, tetapi hanya lapisan paling bawahnya.

Kamu sudah melakukan versi kecil pekerjaan ini di SOC. Saat menerima laporan insiden dari tim lain, kamu tidak meneruskannya utuh ke semua orang. Direksi cukup tahu dampaknya, detection engineer perlu tahu perilaku yang harus dideteksi, dan analyst L1 perlu daftar indikator untuk dicari hari ini. CTI adalah pekerjaan yang sama, dilakukan dengan sengaja untuk ancaman dari luar, dan dimulai dari pertanyaan konsumen, bukan dari sumber yang kebetulan tersedia. Bagimu, CTI juga jembatan antara DFIR (yang menghasilkan temuan) dan detection serta hunting (yang membutuhkan prioritas).

```
Laporan ancaman (satu dokumen)
  -> strategic  : risiko dan tren       -> direksi, CISO         -> anggaran, prioritas program
  -> operational: serangan dekat        -> kepala IR             -> siaga (jarang tersedia)
  -> tactical   : TTP                   -> detection engineer    -> rule dan hunting baru
  -> technical  : IOC (IP, domain, hash) -> SOC, otomasi         -> lookup dan blokir (cepat basi)
Setiap produk harus berakhir di sebuah keputusan; tanpa keputusan, itu hanya informasi.
```

Situasi yang dipakai sepanjang Day ini: Senin pagi, CISO PT Logistik Contoh (PT LC, perusahaan logistik fiktif dengan gudang di Jakarta, Surabaya, dan Medan) meneruskan laporan vendor publik (fiktif) tentang "Kampanye LABA-LABA" yang menyasar perusahaan logistik di Asia Tenggara. Pesannya:

> "Ini relevan buat kita? Tolong siapkan tiga hal sebelum rapat siang: (1) satu paragraf untuk direksi, (2) apa yang harus dicek detection engineer, (3) apa yang dimasukkan SOC ke SIEM hari ini."

Lead SOC menambahkan di thread yang sama:

> "Bukannya kita sudah langganan tiga feed IP? Itu kan sudah threat intel."

Pesan CISO meminta tiga produk untuk tiga konsumen (bagian 1.2 dan 2.2). Komentar Lead SOC menyentuh beda feed dan intelijen (bagian 1.1). Pertanyaan "ini relevan buat kita?" adalah inti seluruh Day.

**Kapan relevan:** saat menentukan prioritas deteksi, memberi konteks pada alert atau insiden, memilih hipotesis hunting, dan memberi briefing manajemen.
**Kapan bukan jawaban:** saat organisasi tidak bisa bertindak atas informasinya. Contoh: daftar hash sementara tidak ada kemampuan mencari hash di endpoint. MWR menyebut ini program yang berfokus pada koleksi dan bukan pada kebutuhan, dan program seperti ini jarang memberi manfaat [S1].

## 1. Konsep inti

### 1.0 Istilah di Day ini

Tabel ini memuat istilah CTI yang muncul di Day ini. Kolom padanan memakai analogi SOC yang sama di semua Day CTI. Baca kolom kedua dulu, lalu kembali ke tabel ini saat menemukan istilah yang terlupa.

| Istilah | Arti singkat | Padanan di SOC |
|---|---|---|
| Threat intelligence (CTI) | Informasi tentang ancaman yang dianalisis supaya bisa dipakai untuk keputusan | Konteks yang membuat alert bisa diprioritaskan: siapa, kenapa, apa berikutnya |
| Feed IOC | Aliran indikator (IP, domain, hash) dari pihak luar | Blocklist atau lookup di SIEM |
| Requirements | Pertanyaan yang ingin dijawab konsumen intelijen | Use case request sebelum menulis rule |
| Konsumen | Orang atau sistem yang memakai produk intelijen untuk keputusan | Stakeholder laporan SOC: direksi, CISO, detection engineer, analyst |
| Strategic | Intel tentang risiko, tren, dan motif untuk keputusan jangka panjang | Ringkasan tren insiden kuartalan untuk direksi |
| Operational | Intel tentang serangan spesifik yang akan datang | Peringatan dari mitra bahwa kita akan diserang minggu ini |
| Tactical | Intel tentang TTP: bagaimana aktor menyerang | Deskripsi perilaku yang menjadi dasar detection rule |
| Technical | Indikator spesifik yang cepat basi | Isi lookup IOC di SIEM |
| TTP | Tactics, techniques, and procedures | Perilaku penyerang yang dipetakan ke ATT&CK |
| Threat hunting | Pencarian proaktif ancaman yang lolos deteksi di telemetri internal | Hunt berbasis hipotesis |
| Bahasa keyakinan | Cara menyatakan seberapa yakin sebuah penilaian, misalnya "moderate confidence" | Confidence pada alert |

### 1.1 Definisi kerja: informasi untuk keputusan

Komentar Lead SOC ("kita sudah langganan tiga feed IP") adalah salah paham yang paling umum. Feed menjawab "indikator apa yang beredar", tetapi tidak menjawab "apakah ini relevan bagi kita dan apa yang harus dilakukan".

MWR/CPNI mendefinisikan intelijen sebagai informasi yang dapat ditindaklanjuti untuk mengubah hasil. Threat intelligence adalah informasi yang membantu keputusan untuk mencegah serangan atau mempercepat penemuannya. Selain itu, intel juga bisa menerangi lanskap risiko tanpa terikat satu keputusan tertentu [S1].

Dua implikasi praktis:

1. Mulai dari kebutuhan (requirements), bukan dari sumber. Program yang gagal biasanya dimulai dengan "kita butuh tim intel" lalu membeli feed, tanpa pertanyaan yang jelas [S1]. Di SOC, ini sama dengan menyalakan semua rule bawaan tanpa tahu use case apa yang ingin ditutup.
2. Feed tidak sama dengan intelijen. MWR mengutip riset yang menemukan tumpang tindih hanya sekitar 1% di antara tiga feed IP populer dengan lebih dari 20.000 alamat [S1]. Data mentah tanpa analisis dan konteks jarang menjawab pertanyaan apa pun. Angkanya berasal dari dokumen 2015, tetapi pelajarannya tetap berlaku.

### 1.2 Empat tipe menurut konsumen (model MWR/CPNI)

Tiga permintaan CISO PT LC sebenarnya meminta tiga tipe intel untuk tiga konsumen. Model MWR membantu memilah laporan LABA-LABA dengan bertanya: siapa yang akan bertindak, dan dalam berapa lama?

MWR mengelompokkan intel berdasarkan siapa yang mengonsumsi dan berapa lama berlakunya [S1]. Tabel berikut adalah acuan utama Day ini; perhatikan kolom konsumen dan horizon, karena keduanya yang menentukan tipe.

| Tipe | Isi | Konsumen utama | Horizon | Bentuk umum |
|---|---|---|---|---|
| Strategic | Informasi tingkat tinggi tentang risiko yang berubah: tren, dampak finansial, motif | Board, eksekutif | Jangka panjang | Prosa: laporan, briefing |
| Operational | Detail serangan spesifik yang akan datang terhadap organisasi | Defenders, kepala IR/security manager | Jangka pendek | Peringatan; jarang tersedia |
| Tactical | TTP: bagaimana aktor menyerang (mis. pencurian kredensial lalu lateral movement dengan alat admin) | Arsitek, sysadmin, defenders | Jangka panjang | White paper, laporan teknis |
| Technical | Indikator spesifik: IP, domain, hash | SOC/IR, sistem otomatis | Jangka pendek (cepat basi) | Feed, daftar IOC |

Catatan penting dari MWR [S1]:

- Operational intel yang sejati sangat langka bagi entitas swasta. Pengetahuan tentang siapa yang akan menyerang, kapan, dan bagaimana biasanya hanya dimiliki pemerintah. Pengecualian yang realistis antara lain hacktivist yang mengumumkan rencana secara terbuka, atau serangan yang dipicu peristiwa dunia nyata.
- Satu laporan bisa berisi beberapa tipe sekaligus. Contohnya: "aktor yang diyakini terkait negara X menyasar sektor Y" (strategic), modus operandi dan tooling (tactical), dan lampiran hash (technical). Laporan publik nyaris tidak pernah berisi operational dalam arti MWR.

### 1.3 Peringatan: istilah tidak konsisten

Saat detection engineer PT LC membaca laporan LABA-LABA, ia menemukan bagian berjudul "Tactical Intelligence" yang isinya daftar hash. Itu bukan salah ketik; vendor memakai label yang berbeda.

Sumber lain memakai pembagian tiga tipe dan menggeser maknanya. Contohnya Flashpoint [S4]:

- Operational = motif, niat, dan TTP aktor.
- Tactical = IOC dan signature untuk SOC.

Artinya, "tactical" di Flashpoint mirip "technical" di MWR, dan "operational" di Flashpoint mirip "tactical" di MWR.

Cara menyikapinya:

- Saat membaca laporan, kebijakan, atau soal ujian, cek definisi yang dipakai sumber itu.
- Di catatan ini, model empat tipe MWR dipakai sebagai acuan karena berbasis konsumen dan didukung dokumen pemerintah Inggris (CPNI/CERT-UK). Saat berbicara dengan tim, sebut contohnya ("TTP" atau "IOC"), bukan hanya label levelnya.
- Definisi "tiers" berbeda antar vendor dan penulis. Saat membaca materi orang lain, cek dulu definisi yang mereka pakai sebelum membandingkan dengan catatan ini.

### 1.4 CTI vs hunting vs IR

Setelah laporan LABA-LABA dipilah, muncul pertanyaan berikutnya: siapa yang memeriksa apakah kampanye ini sudah masuk ke PT LC? Itu bukan pekerjaan CTI, tetapi CTI yang memicunya.

Tabel berikut memisahkan tiga fungsi yang sering tercampur. Perhatikan baris "Data utama": CTI melihat ke luar, hunting dan IR melihat ke dalam.

| | CTI | Threat hunting | Incident response |
|---|---|---|---|
| Pertanyaan inti | Siapa/apa ancamannya, seberapa relevan, apa yang harus dilakukan? | Apakah ancaman itu sudah ada di lingkungan kita tanpa terdeteksi? | Apa yang terjadi, seberapa luas, bagaimana menghentikannya? |
| Data utama | Sumber eksternal + temuan internal | Telemetri internal | Bukti internal di sekitar insiden |
| Keluaran | Produk intelijen untuk keputusan | Temuan/tidak, celah data, deteksi baru | Containment, eradication, laporan |

Hubungannya dua arah. TaHiTI merumuskannya dalam tiga peran [S3]:

1. Intel sebagai titik awal hunting. Laporan tentang aktor yang menyasar sektormu menjadi pemicu hunt.
2. Intel untuk memberi konteks dan mengarahkan hunt. TTP yang ditemukan dipetakan ke ATT&CK untuk mencari TTP terkait (pivoting).
3. Hunting menghasilkan intel. TTP baru yang ditemukan di lingkunganmu menjadi intel untuk dibagikan.

Insiden yang kamu tangani juga menjadi sumber intel internal yang paling relevan, karena itu ancaman yang benar-benar menyasar organisasimu.

### 1.5 Apa yang diinginkan konsumen hari ini

CISO PT LC meminta "satu paragraf untuk direksi", bukan daftar domain. Survei terbaru menunjukkan permintaan seperti itu wajar, dan menunjukkan di mana produk CTI sering gagal.

SANS 2026 CTI Survey (401 responden; modul 67 CISO/CSO) [S2]:

- 91% CISO menilai CTI bernilai, tetapi hanya 26% yang menyebut CTI benar-benar menggerakkan keputusan mereka.
- Prioritas eksekutif: kerentanan yang sedang dieksploitasi aktif (79%) dan TTP adversary spesifik (77%).
- SecOps (71%) kembali menjadi use case CTI nomor satu, melampaui threat hunting.
- Hambatan utama: waktu dan dana (masing-masing 44%). Sebanyak 57% tidak melacak metrik kematangan, dan 49% tidak punya umpan balik efektivitas yang sistematis.

**Penilaian (bukan fakta):** kesenjangan antara "bernilai" dan "menggerakkan keputusan" menunjukkan bahwa produk CTI sering berhenti di deskripsi ancaman dan tidak sampai ke rekomendasi tindakan. Karena itu setiap produk di catatan ini wajib punya bagian rekomendasi dan bahasa keyakinan (Day 03, Day 11).

## 2. Contoh artefak intelijen

Semua isi bagian ini fiktif dan berlabel ilustrasi. Organisasi PT Logistik Contoh dan laporan "Kampanye LABA-LABA" dibuat untuk latihan; tidak ada klaim tentang aktor atau kampanye nyata. Ketiga artefak di bawah adalah bahan jawaban untuk pesan CISO di bagian Ide inti.

### 2.1 Peta konsumen dan kebutuhan (consumer map)

Sebelum memecah laporan, tulis dulu siapa konsumennya dan keputusan apa yang mereka ambil. Tabel ini memaksa kamu menulis keputusan sebelum memilih sumber.

| Konsumen | Keputusan yang dibuat | Tipe intel (MWR) | Frekuensi | Format |
|---|---|---|---|---|
| Direksi | Anggaran keamanan, risiko ekspansi bisnis | Strategic | Kuartalan | Briefing 1 halaman |
| CISO / security manager | Prioritas program, respons terhadap ancaman dekat | Strategic + operational | Bulanan + ad hoc | Brief 2 halaman |
| Detection engineer / arsitek | Rule apa yang dibuat, kontrol apa yang diubah | Tactical | Mingguan | Daftar TTP + ATT&CK ID |
| SOC L1/L2 | Blokir/cari indikator, konteks alert | Technical | Harian | Feed/lookup di SIEM |
| IR | Scoping insiden | Tactical + technical | Saat insiden | Paket IOC + TTP |

Kolom "Keputusan" adalah cikal bakal Priority Intelligence Requirements (Day 02).

### 2.2 Memecah satu laporan (fiktif) menjadi beberapa produk

Ini jawaban langsung untuk tiga permintaan CISO. Laporan fiktif: *"Kampanye LABA-LABA menyasar perusahaan logistik Asia Tenggara lewat email bertema tagihan, mengeksekusi script lewat `mshta.exe`, lalu mencuri kredensial browser. Lampiran: 12 domain, 30 hash."*

| Produk | Isi | Konsumen | Tindakan |
|---|---|---|---|
| Strategic | "Sektor kita disasar kampanye phishing bertema tagihan. Tingkat keyakinan sedang bahwa ini relevan bagi kita (moderate confidence)." | Direksi/CISO | Dukung program awareness + kontrol email |
| Tactical | Eksekusi via `mshta.exe` (ATT&CK T1218.005 System Binary Proxy Execution: Mshta), pencurian kredensial browser (T1555.003 Credentials from Web Browsers) | Detection eng. | Cek apakah ada deteksi `mshta.exe` dari proses Office/email client |
| Technical | 12 domain, 30 hash (di-defang di catatan: `tagihan-contoh[.]example`) | SOC | Masukkan ke lookup SIEM dengan masa berlaku 30 hari |
| Operational | Tidak ada. Laporan tidak menyebut serangan spesifik terhadap PT Logistik Contoh | - | Catat ketiadaannya |

**Cara membaca hasil:** nilai terbesar biasanya ada di baris tactical. Domain dan hash cepat basi [S1], sedangkan perilaku `mshta.exe` bertahan lebih lama dan bisa menjadi hipotesis hunting maupun deteksi.

### 2.3 Technical intel di SIEM lab (contoh lookup Splunk)

Ini cara SOC PT LC menjalankan baris technical di atas. Keluaran di bawah adalah keluaran ilustrasi.

**Asumsi:** CSV `ioc_domains.csv` berisi kolom `domain,source,expires`, diunggah sebagai lookup; log DNS/proxy di `index=proxy` dengan field `dest_host` (cek nama index dan field di lab-mu).

```
index=proxy earliest=-7d
| lookup ioc_domains.csv domain AS dest_host OUTPUT source expires
| where isnotnull(source) AND strptime(expires, "%Y-%m-%d") > now()
| stats count min(_time) AS first max(_time) AS last BY src, dest_host, source
```

- `lookup ... domain AS dest_host`: mencocokkan field log dengan kolom `domain` di CSV.
- `where isnotnull(source)`: hanya baris yang cocok IOC.
- `strptime(expires, ...) > now()`: buang IOC kedaluwarsa. Ini menerapkan sifat "jangka pendek" intel teknis [S1].
- Keluaran ilustrasi: `src=10.0.5.23 dest_host=tagihan-contoh.example source=LABA-LABA count=3`.
- **Kapan gagal:** domain di log memakai subdomain (`www.`) sedangkan CSV tidak, sehingga tidak cocok. Normalisasi dulu, atau pakai wildcard lookup (Day 10).

## 3. Lab praktik

1. Pilih satu advisori publik terbaru (mis. CISA Cybersecurity Advisory). Baca syarat penggunaan dan label TLP-nya bila ada.
2. Pecah isinya ke tabel bagian 2.2 (strategic/operational/tactical/technical). Tulis ulang dengan kata-katamu sendiri, dan sebut penerbit serta tahunnya. Jangan menambah fakta yang tidak ada di laporan.
3. Buat consumer map bagian 2.1 untuk organisasi fiktif pilihanmu.
4. Defang semua IOC (`hxxp`, `[.]`) di catatan.
5. (Lab Splunk) Buat `ioc_domains.csv` berisi domain uji milikmu sendiri atau domain contoh `.example`, unggah sebagai lookup, lalu jalankan query bagian 2.3 setelah membuat trafik uji dari VM lab ke domain itu (mis. lewat entri hosts lokal). Hasil yang diharapkan: VM lab muncul di hasil.
6. Tulis satu paragraf: "Bagian mana dari advisori ini yang paling berguna untuk SOC saya, dan kenapa?"

**Hasil yang sebaiknya tersimpan:**
- Tabel pemecahan laporan lengkap dengan sumber dan tahun.
- IOC di-defang.
- Query lookup menemukan trafik uji.
- Ada satu kalimat berbahasa keyakinan (mis. "moderate confidence").

**Variasi tantangan:** lakukan hal yang sama di Wazuh dengan CDB list. CDB list adalah file teks berisi satu entri per baris dengan format `kunci:nilai` (misalnya `tagihan-contoh.example:LABA-LABA`), yang dirujuk dari rule lewat elemen `<list>` untuk mencocokkan field tertentu. Berbeda dengan lookup Splunk, CDB list tidak punya kolom masa berlaku, jadi IOC kedaluwarsa harus dihapus dari file lalu manager di-restart. Bandingkan beban pemeliharaannya dengan lookup Splunk.

## 4. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Tidak bisa menentukan tipe intel suatu kalimat | Kalimat campuran | Tanya: siapa yang akan bertindak, dan dalam berapa lama? [S1] |
| Lookup IOC tidak pernah match | Format domain/IP berbeda; IOC kedaluwarsa | Normalisasi (lowercase, buang `www.`); cek `expires` |
| Manajemen tidak membaca brief | Isi terlalu teknis/tanpa rekomendasi | Pisahkan produk strategic; tambahkan rekomendasi [S2] |
| Feed menghasilkan banyak FP | IOC basi/tidak relevan | Batasi masa berlaku; nilai relevansi sumber (Day 03) |

## 5. Kesalahan umum dan jebakan

- Menyamakan CTI dengan feed IOC. Itu hanya lapisan technical [S1].
- Memakai label level tanpa definisi. "Tactical" berarti TTP di MWR [S1] tetapi IOC di Flashpoint [S4]. Selalu sebutkan isinya.
- Mengklaim punya "operational intel" dari laporan publik. Menurut MWR, laporan publik hampir tidak pernah berisi detail serangan spesifik terhadapmu [S1].
- Produk tanpa rekomendasi. Ini penjelasan yang masuk akal untuk kesenjangan "bernilai tetapi tidak menggerakkan keputusan" di survei SANS 2026 [S2] (interpretasi).
- Atribusi yang terlalu yakin. Gunakan bahasa keyakinan dan sebut sumber (aturan etika catatan ini).
- `[komunitas, belum terkonfirmasi]` Kebingungan tactical vs operational sering muncul di diskusi praktisi. Artikel vendor yang membahasnya memakai definisi yang berbeda-beda [S5], jadi selalu tanyakan definisi yang dipakai lawan bicara.

## 6. Catatan terkini

Bagian ini menampung tanggal sumber dan perubahan kelembagaan. Berguna saat mengutip sumber, tetapi tidak mengubah cara memilah intel.

- SANS 2026 CTI Survey dirilis lewat rilis pers 19 Mei 2026. Selain angka di bagian 1.5: SecOps kembali menjadi use case teratas, 55% belum punya proses berbagi CTI yang ditinjau aspek hukumnya padahal NIS2 dan Cyber Resilience Act menambah kewajiban di 2026, dan 45% sudah memakai AI dalam program CTI [S2].
- Dokumen MWR/CPNI berasal dari 2015, jadi lebih dari 3 tahun. Taksonominya masih dirujuk luas, tetapi contoh angka (Google trends, overlap feed) sudah tua. Lembaga penerbitnya juga telah berubah: CERT-UK dilebur ke NCSC UK pada 2016, dan CPNI berganti menjadi NPSA pada 2023.
- Vendor CTI (mis. Flashpoint, artikel diperbarui April 2026) masih memakai model tiga tipe dengan makna yang berbeda dari MWR [S4].

## 7. Cheat sheet

```
CTI = informasi untuk KEPUTUSAN (cegah serangan / percepat penemuan / pahami risiko)
MULAI DARI: requirements (keputusan siapa?) -> bukan dari feed

MWR 4 tipe      isi                          konsumen            horizon
Strategic       risiko/tren/motif            board/eksekutif     panjang
Operational     serangan spesifik akan dtg   defenders/head IR   pendek (langka!)
Tactical        TTP                          arsitek/defenders   panjang
Technical       IOC (IP/domain/hash)         SOC/IR/otomatis     pendek (cepat basi)

AWAS: vendor lain -> "tactical"=IOC, "operational"=TTP/kampanye. Sebutkan isinya.
CTI <-> HUNT: intel memicu hunt | intel memberi konteks hunt | hunt menghasilkan intel
Uji tipe: siapa yang bertindak, dalam berapa lama?
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Lead SOC PT LC berkata, "Kita sudah langganan tiga feed IP, jadi kita sudah punya program CTI." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Feed IOC hanya lapisan technical, lapisan paling bawah CTI. Intelijen adalah informasi yang dianalisis supaya bisa dipakai untuk keputusan, dan programnya dimulai dari requirements, bukan dari sumber. MWR juga mengutip riset yang menemukan tumpang tindih hanya sekitar 1% di antara tiga feed IP populer, sehingga menambah feed tidak otomatis menambah jawaban. Pertanyaan yang tepat: keputusan apa yang ingin dibantu feed itu, dan apakah PT LC bisa bertindak atas isinya? Lihat bagian 1.1.

</details>

**2. Skenario keputusan.** Laporan LABA-LABA menulis: "Aktor mengeksekusi script lewat `mshta.exe` dari lampiran email." Menurut model MWR, kalimat ini termasuk tipe apa?

- A. Strategic, karena menyangkut kampanye yang menyasar sektor.
- B. Tactical, karena menjelaskan TTP, yaitu bagaimana aktor menyerang.
- C. Technical, karena menyebut nama file.

<details><summary>Jawaban</summary>

B. Kalimat itu menjelaskan perilaku (TTP), konsumennya detection engineer atau arsitek, dan horizonnya panjang karena perilaku bertahan lebih lama daripada indikator. A keliru karena strategic membahas risiko, tren, dan motif untuk eksekutif. C keliru karena `mshta.exe` di sini adalah bagian dari perilaku, bukan indikator spesifik seperti hash atau domain. Perlu diingat juga bahwa vendor seperti Flashpoint bisa menyebut isi seperti ini "operational", jadi selalu sebut isinya. Lihat bagian 1.2 dan 1.3.

</details>

**3. Pertanyaan jebakan.** Seorang rekan berkata, "Laporan vendor publik ini memberi kita operational intel: kampanye LABA-LABA akan menyerang sektor logistik." Apakah itu operational intel menurut MWR?

<details><summary>Jawaban</summary>

Bukan. Operational intel menurut MWR adalah detail serangan spesifik yang akan datang terhadap organisasi tertentu, dan bagi entitas swasta sangat langka karena biasanya hanya dimiliki pemerintah. Pernyataan bahwa sebuah kampanye menyasar sektor adalah strategic. Laporan publik nyaris tidak pernah berisi operational dalam arti MWR; karena itu tabel di bagian 2.2 mencatat baris operational sebagai "tidak ada". Lihat bagian 1.2 dan 2.2.

</details>

**4. Jelaskan ulang.** Jelaskan kepada Lead SOC dalam tiga kalimat beda CTI, threat hunting, dan incident response, memakai kampanye LABA-LABA sebagai contoh.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "CTI membaca laporan LABA-LABA dari luar, menilai seberapa relevan untuk kita, lalu memberi tahu apa yang perlu diblokir, dideteksi, dan dilaporkan ke direksi. Threat hunting memakai informasi itu untuk mencari di telemetri kita apakah ada eksekusi `mshta.exe` dari email client yang lolos deteksi. Kalau hunt menemukan aktivitas nyata, incident response mengambil alih untuk menentukan seberapa luas, menghentikannya, dan menulis laporannya, dan temuan IR itu kembali menjadi intel internal."

Kesalahan yang sering muncul:
- Menganggap CTI hanya memasukkan IOC ke SIEM.
- Menganggap hubungan CTI dan hunting satu arah; hunting juga menghasilkan intel.
- Menyamakan hunting dengan IR. Hunting mencari ancaman yang belum ketahuan; IR menangani yang sudah ketahuan.

</details>

**5. Skenario keputusan.** CISO ingin satu dokumen saja untuk semua orang. Pilihan mana yang paling tepat?

- A. Satu laporan 15 halaman berisi semua detail, dikirim ke direksi, detection engineer, dan SOC.
- B. Satu laporan dipecah menjadi produk per konsumen: paragraf strategic dengan rekomendasi untuk direksi, daftar TTP dengan ATT&CK ID untuk detection engineer, dan lookup IOC bermasa berlaku untuk SOC.
- C. Kirim lampiran IOC saja, karena itu bagian yang paling bisa ditindaklanjuti.

<details><summary>Jawaban</summary>

B. Konsumen yang berbeda mengambil keputusan yang berbeda dengan horizon yang berbeda, jadi produknya dipecah sesuai consumer map. A keliru karena direksi tidak akan membaca detail teknis, dan survei SANS 2026 menunjukkan produk yang tidak sampai ke rekomendasi jarang menggerakkan keputusan. C keliru karena IOC cepat basi, sedangkan nilai terbesar biasanya ada di baris tactical yang bertahan lebih lama. Lihat bagian 1.2, 1.5, 2.1, dan 2.2.

</details>

**6. Pertanyaan jebakan.** "Survei SANS 2026 menunjukkan 91% CISO menilai CTI bernilai, jadi CTI sudah menggerakkan keputusan di sebagian besar organisasi." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Survei yang sama menunjukkan hanya 26% CISO yang menyebut CTI benar-benar menggerakkan keputusan mereka. Kesenjangan 91% dan 26% itu yang disebut influence gap. Penilaian di catatan ini (bukan fakta dari survei) adalah bahwa produk CTI sering berhenti di deskripsi ancaman dan tidak sampai ke rekomendasi tindakan. Lihat bagian 1.5.

</details>

**7. Interview question (English).** "What's the difference between threat intelligence and a threat feed?"

<details><summary>Sample answer</summary>

"A threat feed is raw data, usually indicators like IPs, domains, and hashes, and it's only the technical layer of intelligence. Threat intelligence is information that has been analysed against our own requirements so that someone can make a decision, whether that's a board deciding on budget, a detection engineer deciding which behaviour to detect, or a SOC analyst deciding what to block today. So I start from the question and the consumer, not from the feed. Indicators also go stale quickly, which is why I put expiry dates on them, and why I usually get more value from the TTPs in a report than from its IOC list."

What makes this answer strong: it defines intelligence by the decision it supports, names different consumers, and shows practical awareness of indicator decay and the higher value of TTPs.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | MWR InfoSecurity, CPNI, CERT-UK: Threat Intelligence: Collecting, Analysing, Evaluating (salinan PDF) | https://www.ismsforum.es/ficheros/descargas/threat-intelligence--collecting-analysing.pdf | primer (dokumen bersama lembaga pemerintah UK) | 2015 (lebih dari 3 tahun); diakses 2026-10-10 | Tinggi untuk taksonomi. Salinan di situs pihak ketiga (ismsforum.es); tahun terbit tidak tercetak jelas di dokumen |
| S2 | SANS: 2026 Cyber Threat Intelligence Survey insights (rilis pers) | https://www.sans.org/press/announcements/2026-cyber-threat-intelligence-survey-insights-report | sekunder | 2026-05-19; diakses 2026-10-10 | Sedang-tinggi. Angka berasal dari rilis pers; laporan penuh memerlukan registrasi |
| S3 | TaHiTI: a threat hunting methodology (whitepaper) | https://www.betaalvereniging.nl/wp-content/uploads/2026/03/TaHiTI-Threat-Hunting-Methodology-whitepaper.pdf | primer | di-host 2026-03; diakses 2026-10-10 | Tinggi. Tiga peran intel dalam hunting |
| S4 | Flashpoint: Three types of threat intelligence | https://flashpoint.io/blog/three-types-of-threat-intelligence/ | sekunder (vendor) | 2025-09-06, diperbarui 2026-04; diakses 2026-10-10 | Sedang. Dipakai sebagai contoh konvensi alternatif |
| S5 | Recorded Future: Tactical threat intelligence | https://recordedfuture.com/blog/tactical-threat-intelligence | sekunder (vendor) | diakses 2026-10-10 | Rendah-sedang. Contoh lain definisi "tactical" yang berbeda dari MWR |

**Catatan sumber:** angka SANS 2026 di bagian 1.5 dan 6 berasal dari rilis pers; cocokkan dengan laporan lengkap bila tersedia. Tahun terbit dokumen MWR (2015) tidak tercetak jelas di salinan PDF dan diambil dari katalog yang merujuknya. Klaim tentang kebingungan istilah di komunitas belum didukung diskusi praktisi yang bisa dirujuk.
