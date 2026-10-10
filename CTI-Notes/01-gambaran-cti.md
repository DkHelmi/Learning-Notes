---
day: 01
title: 'Gambaran CTI: tingkat intelijen, konsumen, dan bedanya dengan hunting dan IR'
researched_on: 2026-10-10
versions_checked: 'MWR InfoSecurity/CPNI/CERT-UK "Threat Intelligence: Collecting, Analysing, Evaluating" (2015); SANS 2026 CTI Survey (rilis pers 19 Mei 2026); TaHiTI whitepaper (versi di-host 2026-03); Flashpoint "Three types of threat intelligence" (Sep 2025, diperbarui Apr 2026)'
---

# Day 01: Gambaran CTI (tingkat, konsumen, dan bedanya dengan hunting dan IR)

Cakupan: definisi kerja CTI, empat tipe intelijen menurut konsumen beserta ketidakkonsistenan istilahnya, hubungan CTI dengan hunting dan IR, serta cara memecah satu laporan ancaman menjadi produk untuk beberapa konsumen.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- mendefinisikan threat intelligence sebagai informasi yang bisa ditindaklanjuti untuk sebuah keputusan; daftar IOC hanya lapisan paling bawahnya.
- membedakan intelijen strategis, operasional, taktis, dan teknis, beserta konsumennya, dan tahu bahwa istilah ini dipakai tidak konsisten antar sumber.
- memecah satu laporan ancaman publik menjadi produk untuk beberapa konsumen.
- menjelaskan hubungan CTI dengan threat hunting dan incident response.

## 2. Konteks singkat

Di SOC, "threat intel" sering berarti feed IP/domain yang masuk ke SIEM. Itu memang bagian dari CTI, tetapi hanya lapisan paling bawah. Dalam catatan ini, CTI diposisikan sebagai fungsi yang menjawab pertanyaan pengambil keputusan:
- Apa yang harus diblokir hari ini?
- Teknik apa yang perlu dideteksi bulan ini?
- Risiko apa yang perlu dianggarkan tahun ini?

Untukmu, CTI adalah jembatan antara DFIR (yang menghasilkan temuan) dan detection/hunting (yang membutuhkan prioritas).

**Kapan CTI dipakai:** saat menentukan prioritas deteksi, memberi konteks pada alert/insiden, memilih hipotesis hunting, dan memberi briefing manajemen.
**Kapan tidak berguna:** saat organisasi tidak bisa bertindak atas informasinya. Contoh: daftar hash sementara tidak ada kemampuan mencari hash di endpoint. MWR menyebut ini program yang "berfokus pada koleksi" dan bukan pada kebutuhan, dan program seperti ini jarang memberi manfaat [S1].

## 3. Konsep inti

### 3.1 Definisi kerja

MWR/CPNI mendefinisikan intelijen sebagai informasi yang dapat ditindaklanjuti untuk mengubah hasil. Threat intelligence adalah informasi yang membantu keputusan untuk mencegah serangan atau mempercepat penemuannya. Selain itu, intel juga bisa menerangi lanskap risiko tanpa terikat satu keputusan tertentu [S1].

Dua implikasi praktis:
1. Mulai dari kebutuhan (requirements), bukan dari sumber. Program yang gagal biasanya dimulai dengan "kita butuh tim intel" lalu membeli feed, tanpa pertanyaan yang jelas [S1].
2. Feed tidak sama dengan intelijen. MWR mengutip riset yang menemukan tumpang tindih hanya sekitar 1% di antara tiga feed IP populer dengan lebih dari 20.000 alamat [S1]. Data mentah tanpa analisis dan konteks jarang menjawab pertanyaan apa pun. (Data ini berasal dari dokumen 2015, jadi angka pastinya sudah tua, tetapi pelajarannya tetap berlaku.)

### 3.2 Empat tipe menurut konsumen (model MWR/CPNI)

MWR mengelompokkan intel berdasarkan siapa yang mengonsumsi dan berapa lama berlakunya [S1]:

| Tipe | Isi | Konsumen utama | Horizon | Bentuk umum |
|---|---|---|---|---|
| Strategic | Informasi tingkat tinggi tentang risiko yang berubah: tren, dampak finansial, motif | Board, eksekutif | Jangka panjang | Prosa: laporan, briefing |
| Operational | Detail serangan spesifik yang akan datang terhadap organisasi | Defenders, kepala IR/security manager | Jangka pendek | Peringatan; jarang tersedia |
| Tactical | TTP: bagaimana aktor menyerang (mis. pencurian kredensial lalu lateral movement dengan alat admin) | Arsitek, sysadmin, defenders | Jangka panjang | White paper, laporan teknis |
| Technical | Indikator spesifik: IP, domain, hash | SOC/IR, sistem otomatis | Jangka pendek (cepat basi) | Feed, daftar IOC |

Catatan penting dari MWR [S1]:
- Operational intel yang sejati sangat langka bagi entitas swasta. Pengetahuan tentang siapa yang akan menyerang, kapan, dan bagaimana biasanya hanya dimiliki pemerintah. Pengecualian yang realistis antara lain hacktivist yang mengumumkan rencana secara terbuka, atau serangan yang dipicu peristiwa dunia nyata.
- Satu laporan bisa berisi beberapa tipe sekaligus. Contohnya: "aktor yang diyakini terkait negara X menyasar sektor Y" (strategic), modus operandi dan tooling (tactical), dan lampiran hash (technical). Laporan publik nyaris tidak pernah berisi operational dalam arti MWR.

### 3.3 Peringatan: istilah tidak konsisten

Sumber lain memakai pembagian tiga tipe dan menggeser maknanya. Contohnya Flashpoint [S4]:
- Operational = motif, niat, dan TTP aktor.
- Tactical = IOC dan signature untuk SOC.

Artinya, "tactical" di Flashpoint mirip "technical" di MWR, dan "operational" di Flashpoint mirip "tactical" di MWR.

**Cara menyikapinya:**
- Saat membaca laporan, kebijakan, atau soal ujian, cek definisi yang dipakai sumber itu.
- Di catatan ini, kita memakai model empat tipe MWR sebagai acuan karena ia berbasis konsumen dan didukung dokumen pemerintah Inggris (CPNI/CERT-UK). Saat berbicara dengan tim, sebut contohnya ("TTP" atau "IOC"), bukan hanya label levelnya.
- Definisi "tiers" berbeda antar vendor dan penulis. Saat membaca materi orang lain, cek dulu definisi yang mereka pakai sebelum membandingkan dengan catatan ini.

### 3.4 CTI vs hunting vs IR

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

### 3.5 Apa yang diinginkan konsumen hari ini

SANS 2026 CTI Survey (401 responden; modul 67 CISO/CSO; rilis pers 19 Mei 2026) [S2]:
- 91% CISO menilai CTI bernilai, tetapi hanya 26% yang menyebut CTI benar-benar menggerakkan keputusan mereka.
- Prioritas eksekutif: kerentanan yang sedang dieksploitasi aktif (79%) dan TTP adversary spesifik (77%).
- SecOps (71%) kembali menjadi use case CTI nomor satu, melampaui threat hunting.
- Hambatan utama: waktu dan dana (masing-masing 44%). Sebanyak 57% tidak melacak metrik kematangan, dan 49% tidak punya umpan balik efektivitas yang sistematis.

**Penilaian (bukan fakta):** kesenjangan antara "bernilai" dan "menggerakkan keputusan" menunjukkan bahwa produk CTI sering berhenti di deskripsi ancaman dan tidak sampai ke rekomendasi tindakan. Karena itu setiap produk di catatan ini wajib punya bagian rekomendasi dan bahasa keyakinan (Day 03, Day 11).

## 4. Contoh artefak intelijen

> Fiktif. Organisasi "PT Contoh Finansial" dan laporan "Kampanye LABA-LABA" dibuat untuk latihan. Tidak ada klaim tentang aktor atau kampanye nyata.

### 4.1 Peta konsumen dan kebutuhan (consumer map)

| Konsumen | Keputusan yang dibuat | Tipe intel (MWR) | Frekuensi | Format |
|---|---|---|---|---|
| Direksi | Anggaran keamanan, risiko ekspansi bisnis | Strategic | Kuartalan | Briefing 1 halaman |
| CISO / security manager | Prioritas program, respons terhadap ancaman dekat | Strategic + operational | Bulanan + ad hoc | Brief 2 halaman |
| Detection engineer / arsitek | Rule apa yang dibuat, kontrol apa yang diubah | Tactical | Mingguan | Daftar TTP + ATT&CK ID |
| SOC L1/L2 | Blokir/cari indikator, konteks alert | Technical | Harian | Feed/lookup di SIEM |
| IR | Scoping insiden | Tactical + technical | Saat insiden | Paket IOC + TTP |

**Kenapa tabel ini dibuat lebih dulu:** tabel ini memaksa kamu menulis keputusan sebelum memilih sumber. Kolom "Keputusan" adalah cikal bakal Priority Intelligence Requirements (Day 02).

### 4.2 Memecah satu laporan (fiktif) menjadi beberapa produk

Laporan fiktif: *"Kampanye LABA-LABA menyasar lembaga keuangan Asia Tenggara lewat email bertema tagihan, mengeksekusi script lewat `mshta.exe`, lalu mencuri kredensial browser. Lampiran: 12 domain, 30 hash."*

| Produk | Isi | Konsumen | Tindakan |
|---|---|---|---|
| Strategic | "Sektor kita disasar kampanye phishing bertema tagihan. Tingkat keyakinan sedang bahwa ini relevan bagi kita (moderate confidence)." | Direksi/CISO | Dukung program awareness + kontrol email |
| Tactical | Eksekusi via `mshta.exe` (ATT&CK T1218.005 System Binary Proxy Execution: Mshta), pencurian kredensial browser (T1555.003 Credentials from Web Browsers) | Detection eng. | Cek apakah ada deteksi `mshta.exe` dari proses Office/email client |
| Technical | 12 domain, 30 hash (di-defang di catatan: `tagihan-contoh[.]example`) | SOC | Masukkan ke lookup SIEM dengan masa berlaku 30 hari |
| Operational | Tidak ada. Laporan tidak menyebut serangan spesifik terhadap PT Contoh | - | Catat ketiadaannya |

**Cara membaca hasil:** nilai terbesar biasanya ada di baris tactical. Domain dan hash cepat basi [S1], sedangkan perilaku `mshta.exe` bertahan lebih lama dan bisa menjadi hipotesis hunting maupun deteksi.

### 4.3 Technical intel di SIEM lab (contoh lookup Splunk)

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

## 5. Lab praktik

1. Pilih satu advisori publik terbaru (mis. CISA Cybersecurity Advisory). Baca syarat penggunaan dan label TLP-nya bila ada.
2. Pecah isinya ke tabel bagian 4.2 (strategic/operational/tactical/technical). Tulis ulang dengan kata-katamu sendiri, dan sebut penerbit serta tahunnya. Jangan menambah fakta yang tidak ada di laporan.
3. Buat consumer map bagian 4.1 untuk organisasi fiktif pilihanmu.
4. Defang semua IOC (`hxxp`, `[.]`) di catatan.
5. (Lab Splunk) Buat `ioc_domains.csv` berisi domain uji milikmu sendiri atau domain contoh `.example`, unggah sebagai lookup, lalu jalankan query bagian 4.3 setelah membuat trafik uji dari VM lab ke domain itu (mis. lewat entri hosts lokal). Hasil yang diharapkan: VM lab muncul di hasil.
6. Tulis satu paragraf: "Bagian mana dari advisori ini yang paling berguna untuk SOC saya, dan kenapa?"

**Hasil yang sebaiknya tersimpan:**
- Tabel pemecahan laporan lengkap dengan sumber dan tahun.
- IOC di-defang.
- Query lookup menemukan trafik uji.
- Ada satu kalimat berbahasa keyakinan (mis. "moderate confidence").

**Variasi tantangan:** lakukan hal yang sama di Wazuh dengan CDB list. CDB list adalah file teks berisi satu entri per baris dengan format `kunci:nilai` (misalnya `tagihan-contoh.example:LABA-LABA`), yang dirujuk dari rule lewat elemen `<list>` untuk mencocokkan field tertentu. Berbeda dengan lookup Splunk, CDB list tidak punya kolom masa berlaku, jadi IOC kedaluwarsa harus dihapus dari file lalu manager di-restart. Bandingkan beban pemeliharaannya dengan lookup Splunk.

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Tidak bisa menentukan tipe intel suatu kalimat | Kalimat campuran | Tanya: siapa yang akan bertindak, dan dalam berapa lama? [S1] |
| Lookup IOC tidak pernah match | Format domain/IP berbeda; IOC kedaluwarsa | Normalisasi (lowercase, buang `www.`); cek `expires` |
| Manajemen tidak membaca brief | Isi terlalu teknis/tanpa rekomendasi | Pisahkan produk strategic; tambahkan rekomendasi [S2] |
| Feed menghasilkan banyak FP | IOC basi/tidak relevan | Batasi masa berlaku; nilai relevansi sumber (Day 03) |

## 7. Kesalahan umum dan jebakan

- Menyamakan CTI dengan feed IOC. Itu hanya lapisan technical [S1].
- Memakai label level tanpa definisi. "Tactical" berarti TTP di MWR [S1] tetapi IOC di Flashpoint [S4]. Selalu sebutkan isinya.
- Mengklaim punya "operational intel" dari laporan publik. Menurut MWR, laporan publik hampir tidak pernah berisi detail serangan spesifik terhadapmu [S1].
- Produk tanpa rekomendasi. Ini penjelasan yang masuk akal untuk kesenjangan "bernilai tetapi tidak menggerakkan keputusan" di survei SANS 2026 [S2] (interpretasi).
- Atribusi yang terlalu yakin. Gunakan bahasa keyakinan dan sebut sumber (aturan etika catatan ini).
- `[komunitas, belum terkonfirmasi]` Kebingungan tactical vs operational sering muncul di diskusi praktisi. Artikel vendor yang membahasnya memakai definisi yang berbeda-beda [S5], jadi selalu tanyakan definisi yang dipakai lawan bicara.

## 8. Catatan terkini

- **SANS 2026 CTI Survey (Mei 2026):** "CTI influence gap" (91% vs 26%). SecOps kembali menjadi use case teratas. 55% belum punya proses berbagi CTI yang ditinjau aspek hukumnya, padahal NIS2 dan Cyber Resilience Act menambah kewajiban di 2026. 45% sudah memakai AI dalam program CTI [S2].
- Dokumen MWR/CPNI berasal dari 2015, jadi lebih dari 3 tahun. Taksonominya masih dirujuk luas, tetapi contoh angka (Google trends, overlap feed) sudah tua. Lembaga penerbitnya juga telah berubah: CERT-UK dilebur ke NCSC UK pada 2016, dan CPNI berganti menjadi NPSA pada 2023.
- Vendor CTI (mis. Flashpoint, artikel diperbarui April 2026) masih memakai model tiga tipe dengan makna yang berbeda dari MWR [S4].

## 9. Cheat sheet

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
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | MWR InfoSecurity, CPNI, CERT-UK: Threat Intelligence: Collecting, Analysing, Evaluating (salinan PDF) | https://www.ismsforum.es/ficheros/descargas/threat-intelligence--collecting-analysing.pdf | primer (dokumen bersama lembaga pemerintah UK) | 2015 (lebih dari 3 tahun); diakses 2026-10-10 | Tinggi untuk taksonomi. Salinan di situs pihak ketiga (ismsforum.es); tahun terbit tidak tercetak jelas di dokumen |
| S2 | SANS: 2026 Cyber Threat Intelligence Survey insights (rilis pers) | https://www.sans.org/press/announcements/2026-cyber-threat-intelligence-survey-insights-report | sekunder | 2026-05-19; diakses 2026-10-10 | Sedang-tinggi. Angka berasal dari rilis pers; laporan penuh memerlukan registrasi |
| S3 | TaHiTI: a threat hunting methodology (whitepaper) | https://www.betaalvereniging.nl/wp-content/uploads/2026/03/TaHiTI-Threat-Hunting-Methodology-whitepaper.pdf | primer | di-host 2026-03; diakses 2026-10-10 | Tinggi. Tiga peran intel dalam hunting |
| S4 | Flashpoint: Three types of threat intelligence | https://flashpoint.io/blog/three-types-of-threat-intelligence/ | sekunder (vendor) | 2025-09-06, diperbarui 2026-04; diakses 2026-10-10 | Sedang. Dipakai sebagai contoh konvensi alternatif |
| S5 | Recorded Future: Tactical threat intelligence | https://recordedfuture.com/blog/tactical-threat-intelligence | sekunder (vendor) | diakses 2026-10-10 | Rendah-sedang. Contoh lain definisi "tactical" yang berbeda dari MWR |

**Catatan sumber:** angka SANS 2026 di bagian 3.5 dan 8 berasal dari rilis pers; cocokkan dengan laporan lengkap bila tersedia. Tahun terbit dokumen MWR (2015) tidak tercetak jelas di salinan PDF dan diambil dari katalog yang merujuknya. Klaim tentang kebingungan istilah di komunitas belum didukung diskusi praktisi yang bisa dirujuk.
