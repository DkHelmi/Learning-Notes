---
day: 01
title: 'Gambaran besar ISMS: PDCA, keluarga ISO/IEC 27000, sertifikasi vs kepatuhan'
researched_on: 2026-10-10
versions_checked: 'ISO/IEC 27001:2022 edisi 3 + Amd 1:2024 (masih edisi berlaku per 2026-10-10); ISO/IEC 27002:2022 edisi 3; ISO/IEC 27005:2022 edisi 4; ISO/IEC 27035-1:2023 edisi 2; ISO/IEC 27000:2026 edisi 6 (3 Jul 2026); SNI ISO/IEC 27001:2022 dan SNI ISO/IEC 27001:2022/Amd.1:2024 (BSN)'
---

# Day 01: Gambaran besar ISMS (PDCA, keluarga ISO/IEC 27000, sertifikasi vs kepatuhan)

Cakupan: apa itu ISMS, bagaimana risiko, kontrol, SoA, bukti, dan audit tersambung dalam satu siklus, peran tiap standar keluarga ISO/IEC 27000, beda selaras dan tersertifikasi, serta letak pekerjaan SOC/IR/forensik di dalamnya.

## Ide inti

ISO/IEC 27001 tidak menyuruh organisasi membeli alat tertentu. Standar ini menetapkan cara mengelola keamanan informasi: organisasi menilai risikonya sendiri, memilih kontrol untuk risiko itu, menjalankannya, lalu bisa membuktikan ke auditor bahwa semuanya benar-benar berjalan dan terus diperbaiki.

Kamu sudah mengenal pola ini dari SOC. Threat model menentukan detection apa yang dibuat, detection dijalankan, kualitasnya di-review lewat metrik dan QA tiket, lalu di-tuning setelah ada miss atau false positive. ISMS adalah pola yang sama, diterapkan ke seluruh keamanan informasi organisasi dan ditulis rapi supaya bisa diaudit pihak luar.

Seluruh Day ini menjelaskan kotak-kotak di diagram berikut:

```
Risiko bisnis
  -> pilih kontrol (Annex A sebagai ruleset acuan)
  -> catat pilihan dan alasannya di SoA
  -> jalankan kontrol                    <- di sini SOC/IR/forensik bekerja
  -> hasilkan bukti (log, tiket, laporan)
  -> diukur dan diaudit
  -> temuan diperbaiki
  -> kembali menilai risiko (siklus berulang)
```

Situasi yang dipakai sepanjang Day ini: Senin pagi, tim sales PT Awan Nusantara (PT AN, penyedia hosting fiktif) meneruskan email dari calon klien sebuah bank:

> "Mohon lampirkan sertifikat ISO/IEC 27001 kalian, dan jelaskan apakah layanan managed VM termasuk dalam scope sertifikat."

Manajer SOC lalu bertanya padamu: "Kalau auditor datang, log dan tiket kita bisa jadi bukti apa?"

Email singkat itu memuat hampir semua isi Day ini: apa yang dimaksud ISO 27001, siapa yang menerbitkan sertifikat, kenapa klien bertanya soal scope, dan di mana posisi SOC.

**Kapan relevan:** organisasi tempatmu bekerja tersertifikasi atau sedang menuju sertifikasi, klien meminta bukti kepatuhan, atau regulator sektor merujuk ISO 27001.
**Kapan bukan jawaban:** ISO 27001 tidak memberi tahu cara mengonfigurasi Splunk atau Wazuh. Ia menetapkan apa yang harus dikelola dan dibuktikan, bukan resep teknis.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Tabel ini memuat semua istilah ISO yang muncul di Day ini. Kolom padanan memakai analogi SOC yang sama di semua Day; tabel lengkapnya ada di README bagian Analogi jangkar. Baca kolom kedua dulu, lalu kembali ke tabel ini saat menemukan istilah yang terlupa.

| Istilah | Arti singkat | Padanan di SOC |
|---|---|---|
| ISMS (information security management system) | Cara organisasi mengelola keamanan informasi berdasarkan risiko | Cara SOC dijalankan (proses, peran, metrik, review), bukan SIEM-nya |
| Risiko | Kemungkinan sesuatu yang buruk terjadi dan seberapa besar dampaknya | Threat model |
| Kontrol | Apa pun yang menurunkan risiko | Detection rule, hardening, prosedur, pelatihan |
| Klausul 4-10 | Bab persyaratan di 27001 yang wajib dipenuhi semua | Cara kerja SOC yang tertulis di SOP |
| Annex A | Lampiran 27001 berisi daftar 93 kontrol acuan | Ruleset bawaan Wazuh atau repo Sigma: tidak semua diaktifkan |
| SoA (Statement of Applicability) | Dokumen yang mencatat kontrol Annex A mana yang dipakai, mana yang tidak, dan alasannya | Coverage matrix detection |
| Scope | Batas bagian organisasi yang dicakup ISMS | Daftar aset dan log source yang masuk monitoring |
| Requirement (shall) vs guidance (should) | Wajib dipenuhi vs saran cara menerapkan | Requirement detection vs runbook cara menulisnya |
| Bukti (evidence) | Artefak yang menunjukkan sesuatu benar-benar dijalankan | Tiket, laporan, dashboard, log |
| Audit | Pemeriksaan apakah praktik sesuai persyaratan dan prosedur | QA tiket: ambil sampel, cocokkan dengan SOP |
| Nonconformity | Persyaratan atau prosedur yang tidak dipenuhi | Finding |
| Continual improvement | Perbaikan terus-menerus berdasarkan hasil pengukuran dan temuan | Tuning detection setelah miss atau false positive |
| Lembaga sertifikasi (CB) | Organisasi yang mengaudit dan menerbitkan sertifikat | CA yang menerbitkan sertifikat TLS |
| Badan akreditasi | Lembaga yang menilai apakah CB layak dipercaya; di Indonesia KAN | Root store yang memutuskan CA mana yang dipercaya |

### 1.1 ISMS: yang membedakan dua SOC dengan SIEM yang sama

Bayangkan dua organisasi yang sama-sama memakai Splunk dengan lisensi dan jumlah log yang sama.

- **Organisasi A:** tidak ada yang tahu log apa yang wajib masuk. Alert ditriage sesuai kebiasaan masing-masing analyst. Tidak ada yang meninjau apakah deteksi masih relevan, dan host yang berhenti mengirim log baru ketahuan saat insiden.
- **Organisasi B:** tahu risiko apa yang ingin ditangani oleh monitoring. Setiap log source punya pemilik. Ada prosedur triage, metrik bulanan, review berkala, dan gap yang ditemukan dicatat lalu diperbaiki.

Alatnya sama, tetapi hanya organisasi B yang punya sistem manajemen. Perbedaan itulah yang disebut ISMS.

Dengan bahasa yang lebih formal, ISMS adalah bagian dari sistem manajemen organisasi yang memakai pendekatan risiko untuk menetapkan, menjalankan, memantau, meninjau, dan meningkatkan keamanan informasi. Isinya kebijakan, peran, prosedur, proses, dan sumber daya. Tujuannya menjaga confidentiality, integrity, dan availability (CIA) informasi [S1].

Yang perlu diingat: ISMS adalah sistem manajemen, bukan produk. Firewall dan SIEM adalah kontrol. ISMS adalah cara organisasi memutuskan kontrol apa yang dibutuhkan, memastikan kontrol itu berjalan, mengukurnya, dan memperbaikinya.

### 1.2 Keluarga ISO/IEC 27000: satu standar untuk satu jenis pertanyaan

Di kantor, pertanyaan tentang ISO datang dalam bentuk yang berbeda-beda: "kita wajib punya apa?", "bagaimana cara menerapkannya?", "bagaimana menilai risikonya?". Setiap pertanyaan dijawab oleh standar yang berbeda. Tabel berikut adalah peta untuk memilih standar yang tepat; cari kolom "Pertanyaan yang dijawab".

| Standar | Isinya | Pertanyaan yang dijawab | Bisa disertifikasi? |
|---|---|---|---|
| ISO/IEC 27000 | Gambaran umum dan kosakata keluarga ISMS | "Istilah ini artinya apa?" | Tidak |
| ISO/IEC 27001 | Persyaratan ISMS: klausul 4-10 dan Annex A [S11] | "Kita wajib punya apa?" | Ya, satu-satunya |
| ISO/IEC 27002 | Panduan penerapan setiap kontrol di Annex A [S5] | "Bagaimana sebaiknya kontrol X diterapkan?" | Tidak |
| ISO/IEC 27005 | Panduan manajemen risiko keamanan informasi [S10] | "Bagaimana menilai dan menangani risiko?" | Tidak |
| ISO/IEC 27035 (seri) | Panduan manajemen insiden keamanan informasi [S6] | "Bagaimana proses penanganan insiden?" | Tidak |

Cara mengingat beda 27001 dan 27002: 27001 memakai kata "shall" (wajib), 27002 memakai "should" (saran). Hubungannya mirip requirement dan runbook di SOC. Requirement berbunyi "harus ada deteksi brute force pada akun admin", sedangkan runbook menjelaskan cara menulis dan menguji deteksinya. Auditor memeriksa requirement, bukan apakah kamu mengikuti runbook kata per kata.

Karena hanya 27001 yang diaudit untuk sertifikasi, kalimat "kami tersertifikasi 27002" selalu keliru.

### 1.3 Isi 27001: bagian yang wajib dan bagian yang dipilih

Saat membuka 27001, kamu menemukan dua jenis isi dengan sifat yang berbeda. Kalau keduanya tercampur di kepala, hampir semua diskusi ISO akan terasa membingungkan.

**Bagian pertama: klausul 4-10, wajib semua.** Klausul ini mengatur cara ISMS dijalankan. Organisasi yang ingin tersertifikasi harus memenuhi semuanya, tanpa pengecualian. Klausul 0-3 hanya pengantar (pendahuluan, ruang lingkup standar, acuan, istilah).

Tabel berikut cukup dibaca sekali untuk mendapat gambaran; setiap klausul dibahas sendiri di Day 02-06.

| Klausul | Judul (singkat) | Gagasan inti | Kotak di diagram Ide inti |
|---|---|---|---|
| 4 | Context of the organization | Pahami organisasi dan pihak berkepentingan, tetapkan scope | Sebelum "risiko bisnis" |
| 5 | Leadership | Komitmen pimpinan, kebijakan, peran dan wewenang | Menopang seluruh siklus |
| 6 | Planning | Menilai dan menangani risiko, sasaran keamanan, SoA | Risiko, pilih kontrol, SoA |
| 7 | Support | Sumber daya, kompetensi, awareness, komunikasi, dokumen | Menopang seluruh siklus |
| 8 | Operation | Menjalankan rencana dan risk treatment | Jalankan kontrol, hasilkan bukti |
| 9 | Performance evaluation | Pemantauan, pengukuran, internal audit, management review | Diukur dan diaudit |
| 10 | Improvement | Perbaikan berkelanjutan, nonconformity, tindakan korektif | Temuan diperbaiki |

Klausul 4-10 memakai kerangka bab yang sama dengan standar sistem manajemen ISO lain seperti ISO 9001 dan ISO 22301, sehingga organisasi yang sudah punya ISO 9001 akan mengenali polanya [S1][S7].

**Bagian kedua: Annex A, dipilih berdasarkan risiko.** Annex A adalah daftar 93 kontrol acuan, dikelompokkan dalam empat tema. Nomor kontrolnya langsung menunjukkan temanya [S5]:

| Tema | Penomoran | Jumlah | Contoh |
|---|---|---|---|
| Organizational | 5.1-5.37 | 37 | 5.7 Threat intelligence |
| People | 6.1-6.8 | 8 | 6.8 Information security event reporting |
| Physical | 7.1-7.14 | 14 | 7.4 Physical security monitoring |
| Technological | 8.1-8.34 | 34 | 8.15 Logging |

Annex A bekerja seperti ruleset bawaan Wazuh atau repo Sigma. Isinya daftar acuan, dan tidak ada yang mengaktifkan semua rule tanpa melihat lingkungannya. Organisasi memilih kontrol berdasarkan hasil penilaian risiko, membandingkan pilihannya dengan Annex A supaya tidak ada kontrol penting yang terlewat, lalu mencatat hasilnya di SoA [S1].

**SoA menyambungkan kedua bagian.** SoA mirip coverage matrix detection: untuk setiap kontrol Annex A, SoA mencatat apakah kontrol itu dipakai, alasannya, dan alasan bila tidak dipakai. Bedanya dengan coverage matrix SOC, SoA adalah dokumen wajib yang dibaca auditor. Kontrol yang tidak dipakai tidak otomatis menjadi masalah, selama alasannya masuk akal dan konsisten dengan penilaian risiko. Cara menyusun SoA dibahas di Day 04.

### 1.4 Siklus perbaikan: PDCA dulu wajib, sekarang kerangka berpikir

Diagram di bagian Ide inti berbentuk siklus, bukan garis lurus. Siklus ini sering dijelaskan dengan PDCA (Plan, Do, Check, Act), dan pertanyaan tentang PDCA sering muncul di interview.

Banyak materi pelatihan memetakan klausul ke PDCA seperti ini [S7]:

| Fase | Klausul | Kotak di diagram |
|---|---|---|
| Plan | 4-6 | Risiko, pilih kontrol, SoA |
| Do | 7-8 | Jalankan kontrol, hasilkan bukti |
| Check | 9 | Diukur dan diaudit |
| Act | 10 | Temuan diperbaiki |

Pemetaan ini membantu memahami alur, tetapi statusnya interpretasi, bukan teks persyaratan. Edisi 2005 memang menyatakan secara eksplisit bahwa ISMS mengikuti PDCA. Sejak edisi 2013 (dan tetap di 2022), 27001 tidak lagi menetapkan model proses tertentu. Yang diwajibkan adalah continual improvement; PDCA tetap sah dipakai, tetapi organisasi boleh memakai model lain [S1].

**Jawaban interview:** bila ditanya "apakah ISO 27001 mewajibkan PDCA?", jawab: "Tidak lagi secara eksplisit sejak 2013. Yang diwajibkan adalah continual improvement, dan PDCA tetap cara umum untuk memahaminya."

### 1.5 Selaras vs tersertifikasi, dan kenapa klien bertanya soal scope

Kembali ke email klien di bagian Ide inti. Klien tidak bertanya "apakah kalian menerapkan ISO 27001?", tetapi meminta sertifikat dan menanyakan scope. Kedua hal itu punya alasan.

**Selaras/patuh (aligned/compliant)** berarti organisasi menerapkan praktik sesuai 27001, tetapi tidak diaudit pihak ketiga terakreditasi. Ini klaim internal. Klien tidak punya cara mudah untuk memeriksanya.

**Tersertifikasi** berarti lembaga sertifikasi (certification body, CB) yang terakreditasi sudah mengaudit ISMS terhadap 27001 dan menerbitkan sertifikat untuk scope tertentu. Rantai kepercayaannya mirip sertifikat TLS:

```
ISO                 menulis standar, tidak menerbitkan sertifikat
Badan akreditasi    menilai dan mengakreditasi CB         (seperti root store)
  (di Indonesia: KAN, Komite Akreditasi Nasional)
CB                  mengaudit organisasi, menerbitkan sertifikat  (seperti CA)
Sertifikat          berlaku untuk scope tertentu           (seperti sertifikat untuk satu domain)
```

Badan akreditasi nasional di berbagai negara saling mengakui hasil akreditasinya lewat pengaturan multilateral. Karena itu sertifikat dari CB terakreditasi di satu negara juga diakui di negara lain [S12]. Lembaga yang mengelola pengakuan internasional ini berganti pada 2026; rinciannya ada di bagian 6.

Batas analogi TLS: tidak ada verifikasi kriptografis. Kepercayaan dibangun lewat audit berkala dengan siklus berikut:

1. **Audit tahap 1:** kesiapan dan dokumen.
2. **Audit tahap 2:** apakah ISMS benar-benar berjalan efektif.
3. **Surveillance audit:** minimal sekali setahun selama masa berlaku sertifikat tiga tahun.
4. **Recertification audit:** di akhir tiga tahun, untuk siklus berikutnya.

Detail aturan audit untuk CB dibahas di Day 13 dan 17.

**Kenapa scope ditanyakan.** Sertifikat bisa hanya mencakup satu data center atau satu layanan. Kalimat "Perusahaan X tersertifikasi ISO 27001" tidak berarti seluruh perusahaan, SOC-nya, atau layanan yang kamu beli ikut diaudit. Klien bank di bagian Ide inti bertanya karena yang mereka beli adalah managed VM; sertifikat yang hanya mencakup layanan lain tidak berguna bagi mereka.

**Di CV.** Sertifikat ISO 27001 dimiliki organisasi, bukan individu. Tulis "berkontribusi pada bukti kontrol logging/insiden untuk ISMS yang tersertifikasi ISO/IEC 27001", bukan "certified ISO 27001". Sertifikasi individu (lead implementer, lead auditor) adalah hal yang berbeda.

### 1.6 Kenapa organisasi mau repot

- **Tuntutan pasar dan kontrak.** Klien dan mitra, terutama di layanan TI, cloud, dan keuangan, meminta bukti seperti email di bagian Ide inti.
- **Regulasi.** Beberapa regulator sektor merujuk atau mendorong standar ini. Di Indonesia, BSN mengadopsi 27001:2022 secara identik sebagai SNI ISO/IEC 27001:2022 [S4]. Rinciannya di bagian 6 dan Day 18.
- **Tata kelola internal.** Keputusan keamanan menjadi berbasis risiko dan terdokumentasi, bukan berbasis selera atau tawaran vendor.
- **Bahasa bersama.** Struktur klausulnya seragam dengan standar sistem manajemen lain, sehingga mudah digabung dengan ISO 9001 atau ISO 22301 [S1].

### 1.7 Di mana SOC/IR/forensik berada

Kembali ke pertanyaan manajer SOC di bagian Ide inti. Pekerjaan SOC muncul di hampir setiap kotak diagram Ide inti:

| Kotak di diagram | Kontribusi SOC/IR/forensik | Klausul/kontrol terkait |
|---|---|---|
| Risiko bisnis | Memberi masukan risiko dari insiden dan threat intelligence | Klausul 6; kontrol 5.7 Threat intelligence |
| Jalankan kontrol | Logging, monitoring, sinkronisasi waktu | Kontrol 8.15 Logging, 8.16 Monitoring activities, 8.17 Clock synchronization [S8] |
| Jalankan kontrol | Menangani insiden dari perencanaan sampai pengumpulan bukti | Kontrol 5.24-5.28 (perencanaan, penilaian, respons, pembelajaran, pengumpulan bukti) |
| Diukur dan diaudit | Metrik SOC (MTTD, MTTR, cakupan log) | Klausul 9 |
| Temuan diperbaiki | Insiden dan temuan forensik menjadi input tindakan korektif dan management review | Klausul 9 dan 10 |

Auditor tidak bertanya "SIEM apa yang kalian pakai". Mereka bertanya "tunjukkan bahwa log yang relevan dibuat, dilindungi, dan ditinjau, dan bahwa hasil tinjauan ditindaklanjuti" [S8]. Jawabannya selalu berupa bukti: prosedur, sampel tiket, catatan review, dan catatan tindak lanjut. Detailnya dibahas di Day 10-13.

## 2. Contoh dokumen / artefak (organisasi fiktif)

> Fiktif: PT Awan Nusantara (PT AN), penyedia layanan hosting kecil di Jakarta dengan 120 karyawan.

### 2.1 Pernyataan scope ISMS (draf)

Ini jawaban PT AN untuk pertanyaan scope dari klien bank di bagian Ide inti. Perhatikan bahwa scope menyebut yang masuk, yang tidak masuk, dan pihak luar yang terkait.

```
Scope ISMS PT Awan Nusantara (draf v0.1)
Mencakup: pengelolaan keamanan informasi untuk layanan "AN-Hosting" (managed VM),
termasuk operasi SOC 24x7, data center Jakarta-1, dan tim Platform Engineering.
Tidak mencakup: divisi pemasaran, kantor cabang Surabaya.
Antarmuka: penyedia colocation (pihak ketiga) untuk listrik dan pendinginan Jakarta-1.
Acuan persyaratan: ISO/IEC 27001:2022 + Amd 1:2024.
```

| Elemen | Kenapa ada |
|---|---|
| Layanan yang dicakup | Klien membeli layanan ini, jadi sertifikasi harus relevan dengan yang mereka beli |
| SOC masuk scope | Bukti logging dan insiden dihasilkan SOC. Jika di luar scope, kontrol deteksi sulit dibuktikan |
| Pengecualian eksplisit | Mencegah salah klaim. Pengecualian harus beralasan |
| Antarmuka pihak ketiga | Risiko yang tidak dikendalikan langsung tetap harus dikelola |
| Acuan versi dan amandemen | Amd 1:2024 mengubah klausul 4.1 dan 4.2 (isu iklim) [S3][S4] |

### 2.2 Tabel pertanyaan dan standar rujukan

Tabel ini menerapkan peta di bagian 1.2 ke pertanyaan yang benar-benar terdengar di kantor PT AN.

| Pertanyaan di kantor | Standar yang dirujuk | Alasan |
|---|---|---|
| "Kontrol apa yang wajib kita punya?" | 27001 klausul 6 dan SoA | Pemilihan berbasis risiko, Annex A sebagai pembanding |
| "Bagaimana sebaiknya log review dijalankan?" | 27002 (panduan kontrol logging) | Panduan penerapan |
| "Skala likelihood dan impact apa yang dipakai?" | 27005 | Panduan risiko |
| "Bagaimana tahapan penanganan insiden?" | 27035-1 | Prinsip dan proses manajemen insiden [S6] |
| "Istilah nonconformity artinya apa?" | 27000 | Kosakata [S2] |

### 2.3 Peta siklus untuk SOC PT AN (interpretasi PDCA)

Tabel ini mengisi diagram Ide inti dengan aktivitas SOC PT AN. Kolom terakhir adalah yang akan diminta auditor.

| Fase | Klausul (pemetaan umum) | Contoh aktivitas SOC | Bukti yang dihasilkan |
|---|---|---|---|
| Plan | 4-6 | Ikut workshop risk assessment: "log server hosting tidak dipantau" | Entri risk register, rencana treatment |
| Do | 7-8 | Onboard log VM ke Wazuh/Splunk; training analyst | Daftar sumber log, catatan pelatihan |
| Check | 9 | Laporan bulanan cakupan log dan MTTR; ikut diaudit internal | Laporan metrik, temuan audit |
| Act | 10 | Perbaiki gap, misalnya clock drift di 5 host | Catatan tindakan korektif |

## 3. Lab praktik

Latihan ISO berupa dokumen untuk organisasi fiktif, bukan lab teknis.

1. Buat organisasi fiktifmu sendiri (sektor, ukuran, 2-3 layanan). Jangan memakai tempat kerja nyata.
2. Tulis pernyataan scope seperti bagian 2.1, termasuk minimal satu pengecualian beralasan dan satu antarmuka pihak ketiga.
3. Isi tabel bagian 2.2 dengan 5 pertanyaan yang sering kamu dengar di SOC.
4. Gambar ulang diagram Ide inti untuk organisasimu, lalu isi tabel bagian 2.3.
5. **Hubungkan ke lab:** di Splunk/Wazuh lab, identifikasi tiga artefak yang bisa menjadi bukti. Contohnya dashboard jumlah sumber log aktif, laporan alert yang ditriage per bulan, dan status sinkronisasi NTP host. Tulis tiap artefak, kotak di diagram yang didukungnya, kontrol/klausul yang mungkin terkait, dan pemiliknya.
6. Tulis dua baris CV yang jujur tentang keterlibatanmu dengan ISMS (atau rencana keterlibatan), tanpa mengklaim sertifikasi pribadi.

**Hasil yang sebaiknya tersimpan:**
- Satu dokumen 1-2 halaman di `latihan/day01-<nama-org-fiktif>.md`.
- Scope menyebut yang masuk, yang tidak, dan antarmuka.
- Setiap baris tabel menunjuk standar yang tepat (27001, 27002, 27005, atau 27035).
- Tidak ada kalimat yang disalin dari teks standar.
- Baris CV tidak menyiratkan sertifikasi individu.

**Variasi tantangan:** jelaskan dalam 5 kalimat kepada manajer non-teknis kenapa "kita pakai Splunk" bukan jawaban atas pertanyaan auditor tentang logging.

## 4. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Bingung apakah sesuatu "wajib" | Mencampur 27001 (shall) dan 27002 (should) | Cek: apakah ada di klausul 4-10, atau dipilih lewat SoA? |
| Scope terlalu luas atau sempit | Tidak dikaitkan dengan layanan dan klien | Mulai dari "apa yang dibeli klien dan apa yang diminta regulator" |
| Jumlah kontrol berbeda di berbagai artikel | Artikel memakai edisi 2013 (114 kontrol) atau salah hitung | Pastikan edisi 2022: 93 kontrol, 37/8/14/34 [S5] |
| Ragu apakah PDCA wajib | Membaca materi berbasis edisi 2005 | Sejak 2013 tidak eksplisit; continual improvement yang wajib [S1] |
| Tidak tahu versi SNI yang berlaku | Dokumen lama masih menyebut SNI edisi 2013 | Acuan saat ini SNI ISO/IEC 27001:2022 dan Amd.1:2024 [S4]; nomor keputusan penetapan dicek di JDIH BSN |

## 5. Kesalahan umum dan jebakan

- "Kami tersertifikasi 27002." Hanya 27001 yang dapat disertifikasi. 27002 adalah panduan.
- Menganggap Annex A sebagai checklist yang wajib dipakai semua. Kontrol dipilih berdasarkan risiko dan dicatat di SoA [S1].
- Mengira ISO menerbitkan sertifikat. Sertifikat diterbitkan lembaga sertifikasi yang terakreditasi.
- Mengabaikan scope. Sertifikat perusahaan belum tentu mencakup sistem yang kamu pegang.
- Mengutip teks standar di dokumen atau repo publik. Itu pelanggaran hak cipta. Cukup nomor, judul singkat, dan kata-katamu sendiri.
- Menyebut PDCA sebagai "persyaratan". Sudah tidak eksplisit sejak 2013 [S1].
- `[komunitas, belum terkonfirmasi]` Praktisi sering menekankan bahwa auditor mencari disiplin operasional (log benar-benar ditinjau dan ditindaklanjuti), bukan hanya kebijakan tertulis [S8]. Ini sejalan dengan klausul 9, tetapi sumbernya sekunder.

## 6. Catatan terkini

Bagian ini menampung detail edisi, tanggal, dan perubahan kelembagaan. Detail ini penting saat memeriksa dokumen atau sertifikat nyata, tetapi tidak perlu dihafal untuk memahami Day ini.

**Edisi yang berlaku (dicek 2026-10-10):**

| Standar | Edisi berlaku |
|---|---|
| ISO/IEC 27000 | Edisi 6, terbit 3 Jul 2026, menggantikan edisi 2018 [S9]. Adopsi Eropa (EN) menyusul 15 Jul 2026. Tidak memengaruhi validitas sertifikat 27001 yang ada [S2] |
| ISO/IEC 27001 | 27001:2022 (edisi 3, terbit Okt 2022) dengan Amd 1:2024 [S11]. Katalog ISO belum mencantumkan edisi baru; cek katalog yang sama bila ada kabar revisi |
| ISO/IEC 27002 | 27002:2022; 93 kontrol dalam 4 tema [S5] |
| ISO/IEC 27005 | 27005:2022, edisi 4, terbit 25 Okt 2022 [S10] |
| ISO/IEC 27035-1 | 27035-1:2023, edisi 2, terbit 13 Feb 2023 [S6]; acuan untuk Day 10 |

**Perubahan dari edisi lama yang masih sering ditemui:**

- Annex A edisi 2022 (93 kontrol, 4 tema) menggantikan 114 kontrol dalam 14 domain di edisi 2013 [S5][S1]. Artikel yang menyebut 114 kontrol memakai edisi lama.
- Kerangka bab yang seragam dengan standar sistem manajemen lain dulu disebut Annex SL, kini Harmonized Structure [S7].
- Edisi 2022 membalik urutan klausul 10: 10.1 continual improvement, 10.2 nonconformity and corrective action, agar seragam dengan standar sistem manajemen lain [S7].

**Amandemen dan adopsi SNI:**

- Amd 1:2024 (Climate action changes) terbit 23 Feb 2024. Isinya menambah pertimbangan isu iklim di konteks organisasi (4.1) dan pihak berkepentingan (4.2) [S3][S4]. Rinciannya di Day 03.
- BSN mengadopsi Amd 1:2024 secara identik sebagai SNI ISO/IEC 27001:2022/Amd.1:2024. Disusun Komtek 35-04 (sekretariat di BSSN), konsensus 21 Jun 2024, jajak pendapat 18 Jul sampai 1 Agu 2024, ditetapkan tahun 2024 [S4]. Nomor keputusan penetapan SNI ISO/IEC 27001:2022 dan masa transisi dari SNI edisi 2013 perlu dicek di JDIH BSN (jdih.bsn.go.id).

**Transisi sertifikat dan lembaga:**

- Masa transisi sertifikat terakreditasi dari 27001:2013 ke 2022 berakhir 31 Oktober 2025. Sejak 30 April 2024, sertifikasi awal dan resertifikasi harus memakai edisi 2022. Sertifikat edisi 2013 yang belum ditransisikan gugur setelah 31 Oktober 2025 [S13], jadi sertifikat edisi 2013 yang masih ditunjukkan pemasok sekarang sudah tidak berlaku.
- Pengaturan saling pengakuan akreditasi selama ini dikenal sebagai IAF MLA. IAF berhenti beroperasi pada 1 Januari 2026, dan fungsinya bersama ILAC dilanjutkan Global Accreditation Cooperation Incorporated (Global ACI), yang menjalankan pengaturan multilateralnya sendiri [S12]. Situs iaf.nu kini berstatus arsip. Dokumen lama tetap menyebut IAF MLA dan IAF MD. Cakupan pengakuan KAN untuk sertifikasi ISMS saat ini perlu dicek di direktori KAN atau daftar penanda tangan Global ACI.
- Aturan audit untuk CB ada di ISO/IEC 17021-1 (semua sistem manajemen) dan ISO/IEC 27006-1:2024 (tambahan khusus ISMS). Dibahas di Day 13 dan 17.

## 7. Cheat sheet

```
ISMS   = sistem manajemen berbasis risiko untuk CIA informasi (bukan alat)
Siklus = risiko -> pilih kontrol -> SoA -> jalankan -> bukti -> ukur/audit -> perbaiki -> ulang

27000  kosakata (2026, ed.6)   27001 PERSYARATAN, satu-satunya yang disertifikasi (2022 + Amd1:2024)
27002  panduan kontrol (2022)  27005 risiko   27035 insiden (27035-1:2023)
shall = wajib (27001)          should = saran (27002)

Klausul 4-10 WAJIB SEMUA:
  4 Context | 5 Leadership | 6 Planning | 7 Support | 8 Operation | 9 Perf. evaluation | 10 Improvement
PDCA (interpretasi): Plan 4-6 | Do 7-8 | Check 9 | Act 10  -- tidak eksplisit wajib sejak 2013

Annex A DIPILIH berdasarkan risiko: 93 kontrol
  5.x Organizational 37 | 6.x People 8 | 7.x Physical 14 | 8.x Technological 34
SoA = tiap kontrol Annex A: dipakai/tidak + alasan (dokumen wajib, dibaca auditor)

Sertifikat: diterbitkan CB terakreditasi (bukan ISO), untuk SCOPE tertentu, siklus 3 tahun
  tahap 1 -> tahap 2 -> surveillance tiap tahun -> recertification
SOC: 8.15 Logging | 8.16 Monitoring | 8.17 Clock sync | 5.7 TI | 5.24-5.28 insiden | klausul 9 metrik
SNI ISO/IEC 27001:2022 (+ Amd.1:2024) = adopsi identik oleh BSN
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** PT Sentosa Data mencantumkan logo "ISO/IEC 27001 Certified" di situsnya. Apakah SOC mereka pasti pernah diaudit?

<details><summary>Jawaban</summary>

Tidak pasti. Sertifikat berlaku untuk scope tertentu, dan scope bisa hanya satu layanan atau satu lokasi. SOC ikut diaudit hanya bila berada di dalam scope atau mendukung layanan yang ada di scope. Langkah yang benar adalah meminta sertifikatnya dan membaca pernyataan scope di sana. Bahkan bila SOC masuk scope, auditor memakai sampling, sehingga tidak semua proses SOC diperiksa satu per satu. Lihat bagian 1.5.

</details>

**2. Pertanyaan jebakan.** Organisasi kecil tanpa ruang server sendiri menandai kontrol 7.4 Physical security monitoring sebagai "tidak dipakai" di SoA. Apakah itu otomatis nonconformity?

<details><summary>Jawaban</summary>

Tidak. Annex A bersifat acuan, dan kontrol dipilih berdasarkan risiko. Yang wajib adalah SoA mencatat keputusan itu beserta alasannya, misalnya "tidak ada fasilitas fisik dalam scope; server berada di penyedia cloud yang dikelola lewat kontrol pemasok". Nonconformity baru muncul bila alasannya tidak ada, tidak masuk akal, atau bertentangan dengan risk register. Lihat bagian 1.3.

</details>

**3. Jelaskan ulang.** Jelaskan beda ISO/IEC 27001 dan 27002 kepada manajer non-teknis dalam tiga kalimat, tanpa memakai kata "klausul", "Annex", atau "kontrol".

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "27001 berisi daftar hal yang wajib dipenuhi organisasi agar keamanan informasinya dikelola dengan benar, dan hanya standar ini yang bisa diaudit untuk sertifikat. 27002 adalah buku panduan yang menjelaskan cara-cara yang disarankan untuk memenuhi kewajiban itu. Jadi auditor memeriksa kita terhadap 27001, sedangkan tim kita memakai 27002 sebagai referensi saat menerapkannya."

Kesalahan yang sering muncul:
- Menyebut 27002 sebagai "versi lain" atau "versi lebih lengkap" dari 27001. Keduanya punya fungsi berbeda.
- Mengatakan 27002 juga bisa disertifikasi.
- Menjelaskan 27002 sebagai "daftar alat yang harus dibeli". Isinya panduan penerapan, bukan daftar produk.

</details>

**4. Skenario keputusan.** Hari ini 2026-10-11. Seorang calon pemasok mengirim sertifikat "ISO/IEC 27001:2013" yang diterbitkan Maret 2023 dan tertulis berlaku sampai Maret 2026. Apa tanggapanmu?

- A. Terima. Sertifikat diterbitkan CB dan nomornya ISO 27001.
- B. Tolak sebagai bukti. Sertifikat itu sudah tidak berlaku, lalu minta sertifikat terbaru berdasarkan edisi 2022 beserta scope-nya.
- C. Terima, karena edisi 2013 dan 2022 isinya sama.

<details><summary>Jawaban</summary>

B. Ada dua alasan. Pertama, tanggal berlaku yang tertulis sudah lewat. Kedua, masa transisi dari edisi 2013 berakhir 31 Oktober 2025, sehingga sertifikat edisi 2013 tidak lagi berlaku apa pun tanggal yang tertulis. A keliru karena tidak memeriksa edisi, masa berlaku, dan scope. C keliru karena edisi 2022 mengubah Annex A (93 kontrol dalam 4 tema, menggantikan 114 kontrol dalam 14 domain) dan beberapa klausul. Saat meminta sertifikat baru, periksa juga scope-nya dan apakah CB-nya terakreditasi. Lihat bagian 1.5 dan 6.

</details>

**5. Pertanyaan jebakan.** Seorang rekan berkata, "ISMS kita belum memenuhi ISO 27001 karena kita tidak memakai PDCA." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Sejak edisi 2013, 27001 tidak menetapkan model proses tertentu. Yang diwajibkan adalah continual improvement. Organisasi boleh memakai PDCA atau model lain, selama perbaikan berkelanjutan bisa dibuktikan, misalnya lewat hasil audit internal, management review, dan tindakan korektif yang selesai. Lihat bagian 1.4.

</details>

**6. Skenario keputusan.** Auditor berkata kepada tim SOC PT AN: "Tunjukkan bahwa log ditinjau." Bukti mana yang paling kuat?

- A. Lisensi Splunk, diagram arsitektur SIEM, dan jumlah GB log per hari.
- B. Prosedur log review, sampel tiket hasil review bulan lalu, dan catatan tindak lanjut dari temuan review itu.
- C. Kebijakan keamanan informasi yang menyebut "semua log wajib ditinjau".

<details><summary>Jawaban</summary>

B. Auditor ingin melihat bahwa kontrol benar-benar berjalan: ada cara kerja yang ditetapkan (prosedur), ada jejak pelaksanaan (tiket), dan ada tindak lanjut (catatan perbaikan). A hanya membuktikan alat dan data ada, bukan bahwa log ditinjau. C hanya membuktikan niat tertulis, bukan pelaksanaan. Lihat bagian 1.7.

</details>

**7. Interview question (English).** "Our job posting says 'familiar with ISO 27001'. What does that mean for a SOC analyst?"

<details><summary>Sample answer</summary>

"It means I understand that ISO 27001 is a risk-based management system standard, not a technical checklist. Only the clauses 4 to 10 are mandatory for everyone; the Annex A controls are selected based on risk and justified in the Statement of Applicability. As a SOC analyst, my daily work produces evidence for controls such as 8.15 Logging, 8.16 Monitoring activities, and the incident management controls 5.24 to 5.28. So in an audit I can show procedures, ticket samples, and follow-up records, and I know to check whether the SOC is inside the certificate scope."

What makes this answer strong: it separates mandatory clauses from selectable controls, names concrete controls, and talks about evidence instead of tools.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | IT Governance Ltd: Comparing ISO 27001:2005 to ISO 27001:2013 (whitepaper) | tautan asli tidak lagi tersedia | sekunder (konsultan) | Okt 2013 | Sedang-tinggi untuk fakta perubahan 2005 ke 2013 (PDCA tidak lagi eksplisit, struktur seragam, peran SoA) |
| S2 | DQS: ISO/IEC 27000:2026 released | https://www.dqsglobal.com/en/explore/blog/iso-iec-27000-2026-released | sekunder (lembaga sertifikasi) | 2026; diakses 2026-10-10 | Sedang-tinggi. Tanggal adopsi EN dan dampak ke sertifikat |
| S3 | ISO committee: ISO/IEC 27001:2022/Amd 1:2024 Climate action changes | https://committee.iso.org/standard/88435.html | primer (katalog ISO) | terbit 2024-02-23; diakses 2026-10-10 | Tinggi untuk judul dan tanggal terbit |
| S4 | BSN: RSNI3 ISO/IEC 27001:2022/Amd.1:2024 | https://bsn.go.id/uploads/attachment/rsni_iso_iec_27001-2022-amd1_1.pdf | primer | 2024; diakses 2026-10-10 | Tinggi. Prakata (adopsi identik, amandemen pertama SNI ISO/IEC 27001:2022, tanggal konsensus dan jajak pendapat) dan susunan komite |
| S5 | Pivot Point Security: The new ISO 27002:2022: what are themes | https://www.pivotpointsecurity.com/the-new-iso-270022022-what-are-themes-and-why-are-they-cool | sekunder (konsultan) | 2022-03-15, diperbarui 2025-02-12; diakses 2026-10-07 | Sedang. Angka 37/8/14/34, cocok dengan penomoran kontrol |
| S6 | ISO committee: ISO/IEC 27035-1:2023 | https://committee.iso.org/standard/78973.html | primer (katalog ISO) | terbit 2023-02-13; diakses 2026-10-10 | Tinggi untuk edisi dan tanggal terbit |
| S7 | BSI: The final stretch of the ISO/IEC 27001 version transition (materi webinar) | https://www.bsigroup.com/globalassets/localfiles/en-th/webinars/document/material/the-final-stretch-of-the-isoiec-27001-version-transition-3-aug-24.pdf | sekunder (lembaga sertifikasi) | Agu 2024 | Sedang. Harmonized Structure dan urutan klausul 10; pemetaan PDCA ke klausul adalah interpretasi |
| S8 | Advisera: ISO 27001 control 8.15 Logging | https://advisera.com/iso27001/control-8-15-logging/ | sekunder (konsultan) | diakses 2026-10-07 | Sedang. Nomor dan judul 8.15 serta gambaran ekspektasi auditor |
| S9 | ISO committee: ISO/IEC 27000:2026 | https://committee.iso.org/standard/84257.html | primer (katalog ISO) | terbit 2026-07-03; diakses 2026-10-10 | Tinggi untuk edisi 6 dan tanggal terbit |
| S10 | ISO committee: ISO/IEC 27005:2022 | https://committee.iso.org/standard/80585.html | primer (katalog ISO) | terbit 2022-10-25; diakses 2026-10-10 | Tinggi untuk edisi 4 dan tanggal terbit |
| S11 | ISO committee: ISO/IEC 27001:2022 | https://committee.iso.org/standard/82875.html | primer (katalog ISO) | terbit 2022-10-25; diakses 2026-10-10 | Tinggi untuk edisi 3, status published, dan satu amandemen (Amd 1:2024) |
| S12 | IAF (situs arsip): pemberitahuan penghentian operasi IAF dan pembentukan Global ACI | https://iaf.nu/en/home/ | primer (IAF) | diakses 2026-10-10 | Tinggi untuk tanggal 1 Januari 2026; tidak merinci nasib pengakuan IAF MLA yang lama |
| S13 | NSAI: ISO/IEC 27001:2022 transition policy | https://www.nsai.ie/certification/management-systems/iso-iec-27001-information-security-management-system/iso-iec-270012022-transition-policy/ | sekunder (lembaga sertifikasi) | diakses 2026-10-10 | Sedang-tinggi. Batas 30 April 2024 dan 31 Oktober 2025 menurut IAF MD 26 |

**Catatan sumber:** pemetaan PDCA ke klausul 4-10 adalah interpretasi materi pelatihan, bukan teks persyaratan. Batas transisi 2013 ke 2022 diambil dari kebijakan transisi satu lembaga sertifikasi yang merujuk IAF MD 26, bukan dari dokumen IAF MD 26 itu sendiri. Nomor keputusan penetapan SNI ISO/IEC 27001:2022 belum ditemukan di sumber yang dipakai, sehingga ditulis sebagai hal yang perlu dicek di JDIH BSN.
