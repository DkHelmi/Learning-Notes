---
day: 07
title: 'Alur triage alert L1: pertanyaan pertama, disposisi, eskalasi, dan handover'
researched_on: 2026-10-14
versions_checked: 'Splunk ES 8.7 (Configure dispositions for findings; Triage findings and finding groups; Sort and filter findings; Configure the urgency for findings; Analyst and team-based queues); Splunk Enterprise 10.6 (Search Reference: lookup, iplocation; halaman diperbarui 2026-09-09); Splunk Lantern "Creating an incident workflow in Splunk Enterprise Security"; Splunk blog "SOC Metrics" (18 Mei 2023); Microsoft Learn "Basic incident tasks for Microsoft Sentinel incidents" (ms.date 2026-07-02)'
---

# Day 07: Alur triage alert L1 (pertanyaan pertama, disposisi, eskalasi, dan handover)

Cakupan: cara analyst L1 memeriksa satu alert sampai ada keputusan yang bisa dipertanggungjawabkan: pertanyaan pertama, enrichment, disposisi (true positive, benign positive, false positive, undetermined) beserta kriterianya, matriks eskalasi ke L2, serta note tiket dan handover shift.

## Ide inti

Triage adalah keputusan cepat berbasis bukti tentang satu alert: aktivitas ini wajar atau tidak, seberapa penting, dan siapa yang mengerjakan langkah berikutnya. Hasil triage bukan hanya status "closed". Hasilnya adalah tiga hal yang dipakai orang lain: disposisi yang benar (dipakai detection engineer untuk tuning dan SOC lead untuk metrik), keputusan eskalasi yang jelas (dipakai L2), dan note yang bisa dibaca ulang tanpa bertanya (dipakai shift berikutnya). Alert yang ditutup tanpa ketiganya sama saja dengan alert yang tidak pernah dilihat.

Kamu sudah mengenal pola ini dari NOC. Alarm link down masuk NMS. L1 NOC tidak langsung mengirim teknisi: ia cek dulu apakah ada maintenance window, apakah alarmnya flapping karena polling bermasalah, dan berapa pelanggan yang terdampak. Setelah itu tiket ditutup dengan kode penyebab (gangguan nyata, pekerjaan terjadwal, alarm palsu karena sensor), atau dieskalasi ke L2 atau tim lapangan sesuai matriks, dan semuanya ditulis di log serah terima shift. Triage alert keamanan memakai urutan yang sama. Bedanya, di SOC ketidakpastian juga alasan untuk eskalasi, dan "alarm palsu" dipecah menurut siapa yang harus memperbaikinya.

```
Alert masuk antrean (finding di ES, atau alert terjadwal / email / tiket)
  -> ambil alih: owner = kamu, status = In progress
  -> pertanyaan pertama: siapa, apa, di mana, kapan, apakah wajar?
  -> enrichment: aset, identitas, reputasi, lokasi
  -> keputusan:
       bukti cukup, aktivitas sah            -> tutup: Benign Positive
       bukti cukup, detection/data salah     -> tutup: False Positive (Logic / Data) + tiket tuning
       bukti cukup, aktivitas berbahaya      -> True Positive + eskalasi L2
       bukti belum cukup / di luar wewenang  -> eskalasi L2, jangan ditutup
  -> note tiket + handover shift
```

Situasi yang dipakai sepanjang Day ini: shift malam di PT Jaringan Anak Bangsa (PT JAB, ISP menengah fiktif dengan SOC internal yang duduk satu lantai dengan NOC). Pukul 02:10 WIB, alert terjadwal "VPN - login gagal massal dari satu sumber" muncul dan sistem tiket membuat SOC-2026-0217. Isi alert: IP `203.0.113.45` mencatat 180 login gagal ke 25 akun VPN berbeda antara 01:52 dan 02:06, dan satu login sukses atas nama `rina.wulandari` pada 02:04. SOC lead menulis di grup shift:

> "Tolong triage SOC-2026-0217. Kalau perlu, eskalasi ke L2 on-call. Jangan ditutup sebelum ada bukti, dan masukkan ke handover jam 07:00."

Pesan itu memuat lima pertanyaan:

1. Apa yang sebenarnya terjadi, dan apakah itu wajar?
2. Konteks apa yang perlu ditempelkan ke alert sebelum memutuskan?
3. Disposisi apa yang tepat, dan bukti apa yang dibutuhkan untuk memilihnya?
4. Kapan alert ini harus dieskalasi ke L2, dan ke siapa?
5. Apa yang ditulis di tiket dan di handover supaya orang lain bisa melanjutkan?

Pertanyaan 1 dijawab di bagian 1.1 dan 1.2, pertanyaan 2 di bagian 1.3, pertanyaan 3 di bagian 1.4 sampai 1.6, pertanyaan 4 di bagian 1.7, dan pertanyaan 5 di bagian 1.8. Bagian 2 menjalankan semuanya untuk SOC-2026-0217.

**Kapan relevan:** setiap kali ada alert, finding, atau laporan masuk ke antrean SOC dan seseorang harus memutuskan apa yang dilakukan dengannya, baik di Enterprise Security maupun di Splunk Enterprise biasa dengan alert terjadwal dan sistem tiket.
**Kapan bukan jawaban:** triage tidak menggantikan investigasi. Bila alert sudah terbukti berbahaya atau ruang lingkupnya belum jelas, pekerjaan pindah ke tahap penentuan risiko, mitigasi, dan evaluasi ulang yang dikerjakan L2 (Day 34). Triage juga bukan tempat menebus detection yang buruk: alert yang 90% berakhir false positive perlu di-tuning, bukan ditriage lebih cepat.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dasar Splunk dari Day 01 sampai Day 06 (index, sourcetype, `stats`, field log Windows dan VPN) tidak diulang di sini. Tabel ini memuat istilah triage dan Enterprise Security (ES) yang dipakai Day ini; cari kolom padanan bila sebuah istilah terasa asing.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Triage | Penilaian awal satu alert: asli atau tidak, seberapa penting, siapa berikutnya | Pemeriksaan pertama alarm di NOC sebelum memanggil teknisi |
| Alert / finding | Hasil detection yang perlu dinilai manusia. Di ES 8 disebut finding (dulu notable event) | Alert yang masuk antrean triage |
| Analyst queue | Daftar finding dan investigation di Mission Control ES 8 (dulu Incident Review) | Antrean tiket SOC |
| Owner | Analyst yang memegang finding atau tiket | Nama penanggung jawab di tiket gangguan |
| Status | Posisi kasus dalam alur kerja (New, In progress, Resolved, Closed) | Status tiket: open, on progress, closed |
| Urgency | Prioritas finding di ES, dihitung dari severity detection dan priority aset atau identitas | Prioritas tiket berdasarkan dampak dan pelanggan terdampak |
| Enrichment | Menambahkan konteks (aset, identitas, reputasi, lokasi) ke alert | Melihat CMDB dan data pelanggan saat ada alarm |
| Disposition (disposisi) | Hasil penilaian: aktivitas ini sebenarnya apa | Kode penutupan tiket gangguan |
| True positive (TP) | Detection benar dan aktivitasnya berbahaya atau tidak sah | Gangguan nyata |
| Benign positive (benign TP) | Detection benar, aktivitasnya nyata, tetapi sah dan diharapkan | Alarm akibat pekerjaan terjadwal |
| False positive (FP) | Aktivitas tidak berbahaya dan detection seharusnya tidak menyala, karena logika atau data salah | Alarm palsu karena threshold salah atau sensor rusak |
| Undetermined | Belum ada disposisi yang valid; default di ES | Tiket yang belum diberi kode penutupan |
| False negative (FN) | Ancaman nyata yang terlewat atau salah dinilai bukan ancaman | Gangguan pelanggan yang tidak memicu alarm |
| Eskalasi | Menyerahkan kasus ke tingkat berikutnya karena dampak, wewenang, atau ketidakpastian | Eskalasi tiket NOC ke L2 atau tim lapangan |
| Handover | Serah terima kasus yang masih terbuka antar shift | Log serah terima shift NOC |

### 1.1 Triage di dalam alur kerja insiden

SOC-2026-0217 datang dari alert terjadwal, bukan dari ES. Di PT JAB itu biasa, karena sebagian pekerjaan L1 masih dilakukan di app Search & Reporting. Pertanyaan pertama: dari mana pun alert datang, apakah langkah triagenya sama?

Jawabannya ya. Splunk Lantern menyusun alur kerja insiden dalam lima tahap, dan dua tahap pertamanya adalah wilayah triage [S6]:

- **Review events.** Pemicu penyelidikan bisa berupa notable event (finding di ES 8), alert action dari scheduled search, email ke SOC, atau tiket help desk. Apa pun sumbernya, langkah pertama sama: tinjau event dan informasi yang menyertainya [S6].
- **Assessment.** Keputusan awal: apakah ini false alarm atau pola yang sudah dikenal dan sering muncul sehingga bisa diabaikan, apakah bisa diturunkan prioritasnya dan ditunda, apakah bisa ditutup dengan komentar singkat. Bila butuh perhatian lebih, triage menetapkan tingkat kepentingan yang menentukan urutan pengerjaan, biasanya dari severity (dampak ke bisnis) dan impact (jumlah pengguna, perangkat, atau layanan terdampak serta kategori alert) [S6].

Tiga tahap berikutnya (Determine risk, Mitigate, Re-assess), beserta metrik waktu seperti MTTR dan dwell time, dibahas di Day 34. Untuk L1, cukup pegang batasnya: triage berakhir saat kamu bisa menutup alert dengan bukti, atau saat kamu menyerahkannya dengan bukti yang sudah terkumpul.

### 1.2 Pertanyaan pertama: siapa, apa, di mana, kapan, apakah wajar

Saat membuka SOC-2026-0217, godaan terbesar adalah langsung menilai dari judul alert. Judul "login gagal massal" tidak memberi tahu apakah ada yang berhasil masuk, apakah akunnya penting, atau apakah sumbernya pentester resmi. Lima pertanyaan berikut memaksa kamu melihat event aslinya dulu.

Tabel ini memetakan lima pertanyaan ke kasus SOC-2026-0217 dan ke tempat jawabannya di Splunk. Perhatikan kolom terakhir: setiap jawaban harus berasal dari data, bukan dari asumsi.

| Pertanyaan | Untuk SOC-2026-0217 | Sumber jawaban |
|---|---|---|
| Siapa | Akun mana yang dicoba, akun mana yang berhasil, siapa pemiliknya | `index=vpn` per `user`, lalu lookup identitas |
| Apa | Brute force atau password spraying? Ada login sukses? | `stats` per `user` dan `action` (bagian 2.1) |
| Di mana | Dari IP mana, ke gateway VPN mana, lalu ke host internal mana setelah masuk | `src` di VPN, lalu logon Windows dari pool IP VPN (bagian 2.4) |
| Kapan | Rentang waktu persis, dan apakah masih berlangsung | `min(_time)` dan `max(_time)`, ulangi search dengan rentang sampai sekarang |
| Apakah wajar | Pernahkah user ini login dari IP atau negara ini? Ada pentest atau change terjadwal? | Baseline 30 hari (bagian 2.2), kalender change dan pentest |

Dua kebiasaan yang membuat pertanyaan ini efektif:

1. **Baca logika detection-nya.** Alert "login gagal massal" menghitung apa, dalam jendela berapa lama, dengan ambang berapa? Tanpa ini kamu tidak bisa membedakan false positive karena logika dari aktivitas sah (bagian 1.5).
2. **Pakai kanal kedua untuk konfirmasi ke pengguna.** Bila kamu ingin bertanya ke Rina "apakah itu kamu?", jangan lewat email atau chat akun yang sama, karena kanal itu bisa ikut dikuasai penyerang. Telepon ke nomor di direktori karyawan adalah kanal kedua yang wajar. Jawaban pengguna adalah bukti pendukung, bukan bukti tunggal.

### 1.3 Enrichment: menempelkan konteks sebelum memutuskan

Login sukses atas nama `rina.wulandari` dari IP yang tidak dikenal adalah satu fakta. Fakta itu bobotnya berubah total bila ternyata Rina juga memegang akun admin `adm.rina`. Enrichment adalah langkah menempelkan konteks semacam itu ke alert.

Empat jenis konteks yang paling sering dipakai L1:

- **Aset.** Host apa ini, siapa pemiliknya, seberapa kritis. Di PT JAB, `JKT-DC01` dan `jkt-radius01` jelas lebih kritis daripada satu workstation.
- **Identitas.** Departemen, atasan, akun lain milik orang yang sama, status kepegawaian.
- **Reputasi.** Apakah IP atau domain ada di daftar indikator internal atau feed yang dipakai SOC.
- **Lokasi.** Negara dan kota dari IP publik.

Di Splunk Enterprise biasa, konteks ini ditempelkan dengan command `lookup`. Sintaksnya mencocokkan field di event dengan kolom di tabel lookup, lalu menambahkan kolom output. Ada dua cara menulis output [S7]:

- `OUTPUT`: nilai dari lookup menimpa field dengan nama yang sama yang sudah ada di event.
- `OUTPUTNEW`: lookup dilewati untuk event yang sudah punya field output itu.
- Tanpa klausa output, semua kolom lookup selain kolom pencocok ditambahkan.

Untuk lokasi, `iplocation` menambahkan field `City`, `Country`, `Region`, `lat`, dan `lon` dari database geolokasi. Alamat privat atau internal tidak mendapat lokasi sama sekali [S8]. Detail lookup, termasuk automatic lookup dan lookup aset, dibahas di Day 12 bagian 1.2 dan Day 26.

Di ES, konteks aset dan identitas sudah ditempelkan otomatis lewat Asset & Identity framework, dan hasilnya masuk ke perhitungan urgency. ES menghitung urgency dari severity event yang dibuat detection dan priority aset atau identitas yang terlibat; bila keduanya punya priority, yang lebih tinggi dipakai, dan analyst boleh mengubah urgency secara manual [S4]. Contohnya, detection dengan severity high pada aset berprioritas critical menghasilkan urgency critical, sedangkan severity informational tetap informational berapa pun priority-nya [S4]. Konsekuensinya untuk L1: urgency hanya sebaik data Asset & Identity. Aset yang tidak terdaftar mendapat priority unknown, sehingga finding penting bisa tampil dengan urgency rendah.

### 1.4 Empat disposisi dasar

Setelah konteks lengkap, kamu harus menjawab "alert ini sebenarnya apa?". Hampir semua SIEM memakai pembagian yang sama, dan memahaminya sebagai empat jawaban dasar lebih penting daripada menghafal label produk.

Tabel berikut membedakan empat disposisi dasar berdasarkan dua pertanyaan: apakah detection bekerja seperti yang dimaksud, dan apakah aktivitasnya berbahaya. Gunakan dua kolom tengah untuk memeriksa pilihanmu.

| Disposisi | Detection bekerja benar? | Aktivitas berbahaya atau tidak sah? | Contoh di PT JAB |
|---|---|---|---|
| True positive | Ya | Ya | Penyerang menebak password lalu masuk VPN sebagai `rina.wulandari` |
| Benign positive (benign TP) | Ya | Tidak, sah dan diharapkan | Vendor pentest resmi menjalankan uji password spraying sesuai jadwal dan nomor change |
| False positive | Tidak | Tidak | Detection menghitung event "session timeout" sebagai login gagal; atau log VPN salah zona waktu sehingga 25 login normal tampak terjadi dalam 15 menit |
| Undetermined | Belum diketahui | Belum diketahui | Bukti belum cukup untuk memilih salah satu di atas |

Definisi resmi menekankan hal yang sama. Benign positive adalah finding yang awalnya mencurigakan tetapi kemudian dinilai tidak berbahaya dan memang diharapkan, sedangkan false positive adalah finding yang dinilai tidak berbahaya karena logika analitik yang salah atau data yang tidak akurat [S1]. Microsoft Sentinel memakai lima klasifikasi penutupan yang sejajar: true positive (aktivitas mencurigakan), benign positive (mencurigakan tetapi diharapkan), false positive karena logika alert salah, false positive karena data salah, dan undetermined [S10]. Jadi kosakata ini bukan kebiasaan satu vendor.

Kenapa benign positive dipisah dari false positive: pada benign positive, detection sudah benar dan tidak boleh "diperbaiki" logikanya. Yang dibutuhkan paling jauh adalah pengecualian sempit dan terkelola (misalnya IP pentester selama periode change). Bila benign positive dicatat sebagai false positive, detection engineer bisa melemahkan rule yang sebenarnya bekerja.

Pasangan dari false positive adalah false negative. Blog SOC metrics Splunk mendefinisikan FP rate sebagai persentase yang diklasifikasikan sebagai insiden padahal bukan ancaman nyata, dan FN rate sebagai persentase yang diklasifikasikan bukan ancaman padahal ancaman nyata [S9]. Untuk L1, FN paling sering lahir dari satu kebiasaan: menutup alert sebagai FP tanpa bukti karena "biasanya juga FP".

### 1.5 Tujuh disposition bawaan ES 8.7

Bila SOC-2026-0217 muncul sebagai finding di ES, empat disposisi dasar tadi tersedia sebagai tujuh label bawaan. Tabel ini adalah daftar yang akan kamu lihat di drop-down Disposition; perhatikan kolom "Kapan dipakai" untuk dua label FP yang sering tertukar.

| Disposition | Arti menurut dokumentasi ES | Kapan dipakai |
|---|---|---|
| Undetermined | Default; finding belum punya disposisi yang valid [S1] | Belum dianalisis. Jangan dibiarkan saat menutup |
| True Positive - Suspicious Activity | Finding menunjukkan aktivitas ancaman yang mencurigakan [S1] | Aktivitas berbahaya atau tidak sah yang terkonfirmasi atau sangat mungkin |
| Benign Positive - Suspicious But Expected | Awalnya mencurigakan, lalu dinilai tidak berbahaya dan diharapkan [S1] | Detection benar, aktivitasnya sah: admin menjalankan alat, pentest resmi, perubahan terjadwal |
| False Positive - Incorrect Analytic Logic | Tidak berbahaya karena logika analitik salah [S1] | Detection menangkap hal di luar tujuannya; logika perlu diperbaiki |
| False Positive - Inaccurate Data | Tidak berbahaya karena data tidak akurat [S1] | Parsing salah, timestamp salah, field CIM keliru; data atau add-on perlu diperbaiki |
| Other | Kategori serba ada untuk yang tidak terklasifikasi [S1] | Jarang; selalu beri catatan alasannya |
| Testing | Untuk menguji input field dan drilldown search [S1] | Uji detection di lab |

Pengaturan yang perlu kamu ketahui walaupun yang mengubahnya admin [S1]:

- Disposition dipilih di detail finding dari analyst queue Mission Control, lewat drop-down Disposition, lalu Save Changes.
- Daftar disposition dikelola di Configure > Findings and investigations > Dispositions. Semua disposition aktif secara default, dan masing-masing bisa dimatikan.
- Toggle Required membuat disposition wajib diisi sebelum finding bisa ditutup.
- Disposition kustom ditambahkan lewat +Disposition dengan label dan deskripsi, dan salah satunya bisa dijadikan default.
- Mengisi disposition tidak mengubah status finding. Status (misalnya New, In-progress, Closed) dan disposition adalah dua field terpisah.

Poin terakhir sering disalahpahami. Status menjawab "kasus ini sedang di mana dalam alur kerja", disposition menjawab "hasil penilaiannya apa". Finding bisa berstatus Closed dengan disposition True Positive, dan bisa berstatus In-progress dengan disposition Undetermined. Metrik membutuhkan keduanya.

### 1.6 Kriteria memilih disposisi dan siapa yang menindaklanjuti

Disposisi yang benar adalah bahan bakar tuning: FP rate per detection hanya bisa dihitung bila analyst memberi disposisi yang konsisten. Karena itu setiap disposisi butuh bukti minimum, dan setiap disposisi mengarah ke pemilik tindak lanjut yang berbeda.

Tabel berikut adalah kriteria kerja yang dipakai di catatan ini. Kolom "Bukti minimum" adalah yang harus tertulis di note sebelum disposisi dipilih; kolom terakhir menunjukkan ke mana tiket lanjutan dikirim.

| Disposisi | Bukti minimum di note | Tindak lanjut dan pemiliknya |
|---|---|---|
| True Positive | Event yang menunjukkan aktivitas tidak sah, misalnya login sukses dari sumber asing yang diikuti akses internal | Eskalasi L2 untuk scoping dan containment |
| Benign Positive | Bukti bahwa aktivitas sah: nomor change, jadwal pentest, konfirmasi pemilik aset lewat kanal kedua | Pertimbangkan pengecualian sempit dan berbatas waktu; detection tidak diubah |
| FP - Incorrect Analytic Logic | Contoh event yang tertangkap padahal di luar tujuan detection, dan penjelasan bagian logika yang salah | Tiket tuning ke detection engineer |
| FP - Inaccurate Data | Contoh event dengan field atau timestamp salah, dibandingkan dengan `_raw` | Tiket ke data atau platform engineer (add-on, parsing, zona waktu) |
| Undetermined | Daftar yang sudah dicek dan yang belum bisa dicek | Tidak ditutup; eskalasi atau tunda dengan alasan tertulis |

Pemisahan dua jenis FP membuat tahap Re-assess (Day 34) mengarah ke orang yang tepat. FP karena logika adalah pekerjaan detection engineer; FP karena data adalah pekerjaan pengelola add-on dan onboarding (Day 28). Bila keduanya dicampur, tidak ada yang merasa tiketnya miliknya.

**Tanpa ES:** di PT JAB, alert terjadwal dari Search & Reporting masuk ke sistem tiket, bukan ke analyst queue. Kosakata disposisinya tetap sama (tujuh label di bagian 1.5) supaya metrik dari dua jalur bisa digabung. Field disposisi di form tiket dibuat wajib saat status diubah ke closed, meniru toggle Required di ES. Urgency tidak dihitung otomatis, jadi L1 menentukan prioritas dari matriks eskalasi di bagian 1.7.

### 1.7 Kriteria eskalasi L1 ke L2

Kembali ke SOC-2026-0217: ada login sukses setelah rangkaian gagal. Apakah L1 boleh menyelesaikannya sendiri? Matriks eskalasi menjawab pertanyaan itu sebelum kejadian, supaya keputusan pukul dua pagi tidak bergantung pada keberanian masing-masing analyst.

Eskalasi punya tiga alasan yang berbeda: dampak (aset atau akun penting terlibat), wewenang (tindakan yang dibutuhkan di luar hak L1, misalnya menonaktifkan akun), dan ketidakpastian (bukti tidak cukup untuk memilih disposisi). Alasan ketiga inilah yang membedakan SOC dari NOC: di SOC, "saya tidak yakin" adalah alasan eskalasi yang sah.

Tabel berikut adalah contoh matriks eskalasi di PT JAB. Isinya kebijakan organisasi fiktif, bukan aturan produk; gunakan kolom pertama untuk mencocokkan kondisi alert yang sedang kamu pegang.

| Kondisi | Contoh | Tindakan L1 | Ke siapa |
|---|---|---|---|
| Login sukses setelah rangkaian gagal dari sumber tak dikenal | SOC-2026-0217 | Eskalasi segera, disposisi sementara Undetermined atau True Positive bila bukti sudah jelas | L2 on-call |
| Akun admin atau service terlibat | `adm.rina`, `svc_backup`, `svc_billing` | Eskalasi segera | L2 on-call |
| Aset kritis terlibat | `JKT-DC01`, `JKT-DC02`, `jkt-radius01`, `jkt-billing01` | Eskalasi segera | L2 on-call, beri tahu NOC bila layanan pelanggan berisiko |
| Butuh tindakan di luar wewenang L1 | Menonaktifkan akun, memblokir IP pelanggan korporat | Eskalasi dengan rekomendasi tindakan | L2, lalu pemilik sistem |
| Bukti tidak cukup setelah pemeriksaan standar | Data sumber tidak tersedia, pengguna tidak bisa dihubungi | Eskalasi sebagai Undetermined dengan daftar yang belum dicek | L2 pada jam kerja, atau on-call bila urgency high ke atas |
| Aktivitas sah terverifikasi | Pentest resmi dengan nomor change | Tutup sebagai Benign Positive | Tidak ada eskalasi |
| Detection jelas salah logika atau data | Event timeout dihitung sebagai gagal | Tutup sebagai FP yang sesuai, buat tiket tuning | Detection engineer atau platform engineer |

Di ES 8.7, routing ke tim bisa dibantu dengan team-based queue. Admin mendefinisikan kondisi yang menentukan finding dan investigation mana yang masuk ke setiap queue; item yang tidak cocok dengan kondisi mana pun tetap di queue default, yang menurut dokumentasi sering dipakai analyst Tier 1 atau SOC lead [S5]. Dua batasan yang perlu diingat: finding group hanya di-routing sekali saat triage sehingga perubahan berikutnya tidak memindahkannya otomatis, dan team queue mengatur apa yang tampil di ruang kerja, bukan siapa yang boleh mengakses data [S5].

### 1.8 Note tiket dan handover shift

Pukul 07:00, analyst shift pagi membuka SOC-2026-0217 tanpa pernah melihat search yang kamu jalankan. Note tiket adalah satu-satunya jembatan, jadi tulis seolah pembacanya tidak bisa bertanya.

Lantern menganjurkan agar detail investigasi dan lampiran dicatat sebagai note, termasuk percakapan lewat telepon, email, dan chat, supaya orang lain bisa mengikuti langkahmu; riwayat tindakan dan note yang terkini membuat analyst lain bisa mengambil alih pekerjaan [S6]. Di ES 8.7, admin bisa mewajibkan note: saat kamu menyimpan perubahan owner, status, urgency, atau disposition, muncul dialog Add note [S2].

Template note L1 yang dipakai di catatan ini punya empat bagian tetap, ditambah keterbatasan:

```
Yang dilihat   : alert apa, kapan, entitas apa (user, src, host), logika detection-nya
Yang dicek     : setiap pemeriksaan + query atau rentang waktunya + hasilnya (angka, bukan kesan)
Kesimpulan     : disposisi (atau Undetermined) + alasan satu kalimat + tingkat keyakinan
Langkah berikut: siapa melakukan apa, kapan, dan nomor tiket turunannya
Keterbatasan   : apa yang belum bisa dicek dan kenapa
```

Handover shift adalah ringkasan semua kasus yang masih terbuka, bukan salinan semua note. Isinya per kasus: nomor tiket, status dan owner sekarang, satu kalimat situasi, hal yang ditunggu (misalnya jawaban pengguna atau keputusan L2), dan tenggat bila ada. Kasus yang sudah dieskalasi tetap masuk handover sampai L2 mengonfirmasi bahwa kasus itu sudah diambil alih.

## 2. Contoh SPL dan langkah triage untuk SOC-2026-0217

Semua keluaran di bagian ini adalah keluaran ilustrasi untuk organisasi fiktif PT JAB, bukan hasil eksekusi nyata. Asumsi data: log VPN di `index=vpn` dengan field gaya CIM Authentication (`user`, `src`, `action` bernilai `success` atau `failure`); nama field persis bergantung pada add-on vendor VPN, jadi cek di instance-mu (log VPN dibahas di Day 05). Pool IP VPN karyawan diasumsikan `10.10.250.0/24`. Waktu ditulis dalam WIB sesuai preferensi zona waktu user.

### 2.1 Melihat event di balik alert

Langkah pertama untuk pertanyaan "apa yang terjadi": buka event aslinya, jangan hanya membaca judul alert.

**Tujuan:** memastikan isi alert (jumlah percobaan, jumlah akun, rentang waktu) dan melihat apakah ada login sukses.

```
index=vpn src="203.0.113.45" earliest="10/14/2026:01:30:00" latest="10/14/2026:02:30:00"
| stats count AS attempts dc(user) AS users values(action) AS actions min(_time) AS first max(_time) AS last BY src
| convert ctime(first) ctime(last)
```

- `earliest` dan `latest` absolut: rentang dikunci di sekitar alert, sehingga search bisa diulang besok dengan hasil yang sama. Format default-nya `%m/%d/%Y:%H:%M:%S`.
- `dc(user)`: jumlah akun berbeda. Angka tinggi dengan sedikit percobaan per akun mengarah ke password spraying; banyak percobaan ke satu akun mengarah ke brute force.
- `values(action)`: apakah ada `success` di antara `failure`.
- `convert ctime(...)`: mengubah epoch menjadi waktu yang terbaca.

Keluaran ilustrasi:

```
src            attempts  users  actions          first                 last
203.0.113.45   181       25     failure success  10/14/2026 01:52:07   10/14/2026 02:06:41
```

**Cara membaca hasil:** 181 percobaan terdiri dari 180 gagal dan 1 sukses, cocok dengan alert. Rata-rata sekitar tujuh percobaan per akun dalam 15 menit adalah campuran spraying dan brute force. Yang mengubah prioritas adalah kata `success`.

**Variasi:** pecah per akun untuk melihat siapa yang berhasil:

```
index=vpn src="203.0.113.45" earliest="10/14/2026:01:30:00" latest="10/14/2026:02:30:00"
| stats count(eval(action="failure")) AS gagal count(eval(action="success")) AS sukses BY user
| sort - sukses - gagal
```

Keluaran ilustrasi (lima baris teratas dari 25):

```
user             gagal  sukses
rina.wulandari   7      1
andi.pratama     8      0
budi.santoso     8      0
dewi.lestari     8      0
eko.saputra      8      0
```

Totalnya: lima akun dengan 8 gagal dan dua puluh akun dengan 7 gagal, sehingga 40 + 140 = 180 gagal.

**Kapan gagal:** bila add-on VPN tidak menormalkan nilai `action`, nilainya bisa `Login failed`, `REJECT`, atau kode angka. Jalankan `stats count BY action` dulu untuk melihat nilai yang ada.

### 2.2 Apakah wajar: baseline login pengguna

Pertanyaan "apakah wajar" dijawab dengan membandingkan login sukses malam ini dengan kebiasaan Rina.

**Tujuan:** melihat dari IP dan lokasi mana `rina.wulandari` biasa login VPN dalam 30 hari terakhir.

```
index=vpn user="rina.wulandari" action="success" earliest=-30d@d latest=now
| iplocation src
| stats count min(_time) AS first_seen max(_time) AS last_seen BY src Country City
| convert ctime(first_seen) ctime(last_seen)
| sort - count
```

- `earliest=-30d@d`: 30 hari ke belakang, dibulatkan ke awal hari. Rentang relatif aman di sini karena `index=vpn` adalah data live.
- `iplocation src`: menambahkan `Country` dan `City` [S8].
- `BY src Country City`: satu baris per kombinasi sumber dan lokasi.

Keluaran ilustrasi:

```
src             Country     City      count  first_seen            last_seen
198.51.100.23   Indonesia   Jakarta   41     09/15/2026 07:58:12   10/13/2026 21:40:05
198.51.100.140  Indonesia   Bandung   3      09/22/2026 08:10:44   09/24/2026 17:02:19
203.0.113.45    Netherlands Amsterdam 1      10/14/2026 02:04:13   10/14/2026 02:04:13
```

Lokasi di keluaran ini diisi supaya contoh terbaca. Di data nyata, alamat rentang dokumentasi seperti `203.0.113.0/24` dan `198.51.100.0/24` tidak akan punya lokasi.

**Cara membaca hasil:** dalam 30 hari, Rina login dari dua IP di Indonesia; IP `203.0.113.45` muncul pertama kali tepat saat serangan. Ini belum membuktikan kompromi (Rina bisa saja memakai VPN pribadi), tetapi menghapus penjelasan "itu kebiasaan dia".

**Kapan gagal:** IP privat dan internal tidak mendapat lokasi [S8], dan database geolokasi bisa salah untuk IP seluler atau cloud. Lokasi adalah petunjuk, bukan bukti.

### 2.3 Enrichment identitas dan reputasi

Langkah ini menjawab pertanyaan kedua dari SOC lead: konteks apa yang mengubah bobot alert.

**Tujuan:** menempelkan data identitas dan reputasi ke login sukses.

**Asumsi:** lookup `jab_identities.csv` (kolom `identity`, `department`, `manager`, `priority`, `other_accounts`) dan `jab_ip_reputation.csv` (kolom `ip`, `verdict`, `source`) sudah dibuat sebagai lookup table. Keduanya fiktif.

```
index=vpn src="203.0.113.45" action="success" earliest="10/14/2026:01:30:00" latest="10/14/2026:02:30:00"
| lookup jab_identities.csv identity AS user OUTPUT department manager priority AS user_priority other_accounts
| lookup jab_ip_reputation.csv ip AS src OUTPUTNEW verdict source AS intel_source
| table _time user department manager user_priority other_accounts src verdict intel_source
```

- `identity AS user`: kolom `identity` di lookup dicocokkan dengan field `user` di event [S7].
- `OUTPUT ... priority AS user_priority`: kolom diganti nama saat ditambahkan, supaya tidak bentrok dengan field lain.
- `OUTPUTNEW` pada lookup reputasi: bila event sudah punya `verdict` dari sumber lain, nilainya tidak ditimpa [S7].

Keluaran ilustrasi:

```
_time                user            department        manager        user_priority  other_accounts  src           verdict      intel_source
2026-10-14 02:04:13  rina.wulandari  IT Infrastruktur  budi.santoso   high           adm.rina        203.0.113.45  bruteforce   feed-internal
```

**Cara membaca hasil:** dua fakta baru: IP sudah dikenal sebagai sumber brute force di feed internal, dan pemilik akun juga memegang `adm.rina`. Menurut matriks bagian 1.7, keterlibatan akun admin sudah cukup untuk eskalasi segera.

**Variasi:** bila reputasi diambil dari layanan luar lewat workflow action atau API, ingat bahwa nilai field ikut terkirim ke pihak ketiga. Untuk IP penyerang itu wajar; untuk nama akun internal tidak.

**Kapan gagal:** lookup tidak cocok karena beda format (`JAB\rina.wulandari` vs `rina.wulandari`, huruf besar vs kecil). Normalisasi dulu dengan `eval user=lower(...)` dan buang prefix domain.

### 2.4 Setelah login sukses: apakah akun itu dipakai masuk ke dalam

Login VPN sukses baru menjadi insiden bila sesi itu dipakai. Pemeriksaan ini masih bagian triage karena menentukan seberapa cepat eskalasinya.

**Tujuan:** mencari logon Windows dari pool IP VPN setelah 02:04.

**Asumsi:** log Windows Security di `index=wineventlog` dengan field dari Splunk Add-on for Microsoft Windows (`EventCode`, `user`, `src_ip`, `dest`, `Logon_Type`); detail event 4624 dan logon type ada di Day 03.

```
index=wineventlog EventCode=4624 src_ip="10.10.250.*" earliest="10/14/2026:02:04:00" latest="10/14/2026:02:40:00"
| stats count min(_time) AS first values(dest) AS dest values(Logon_Type) AS logon_type BY user src_ip
| convert ctime(first)
```

Keluaran ilustrasi:

```
user             src_ip         count  first                 dest         logon_type
rina.wulandari   10.10.250.17   2      10/14/2026 02:07:31   JKT-FS01     3
adm.rina         10.10.250.17   1      10/14/2026 02:11:02   JKT-JUMP01   10
```

**Cara membaca hasil:** IP VPN yang sama (`10.10.250.17`) dipakai untuk logon jaringan ke file server, lalu logon RemoteInteractive (type 10) ke jump host dengan akun admin. Ini aktivitas tidak sah yang sangat mungkin, sehingga disposisi True Positive punya dasar, dan kasus harus segera pindah ke L2.

**Kapan gagal:** pada format klasik, event 4624 memuat dua akun (Subject dan target), sehingga `user` bisa multivalue dan berisi akun mesin. Periksa `_raw` untuk satu event sebelum menyimpulkan. Pool IP VPN juga bisa dipakai ulang oleh pengguna lain setelah sesi berakhir, jadi cocokkan dengan log assignment IP dari VPN.

### 2.5 Bila alert yang sama datang sebagai finding di ES 8.7

Search head ES PT JAB juga menjalankan detection serupa. Bila SOC-2026-0217 muncul sebagai finding, urutan triage di Mission Control adalah sebagai berikut [S2][S3]:

1. Buka Mission Control. Analyst queue secara default menampilkan item yang dibuat atau diubah dalam 24 jam terakhir; admin bisa mengubah jendela itu, misalnya ke 48 jam, 72 jam, atau 7 hari [S3]. Bila finding lebih tua, sesuaikan filternya.
2. Pakai view "Unassigned" untuk melihat item yang belum punya owner, lalu pilih nama finding [S3].
3. Isi Owner (dirimu) dan Status (In-progress) supaya tidak ada pekerjaan ganda. Bila admin mewajibkan note, simpan perubahan lalu isi dialog Add note [S2].
4. Tinjau risk score terkait, buka detection yang memicu finding untuk membaca logikanya, dan jalankan drill-down search untuk konteks [S2]. Finding group hanya menampilkan 100 finding dan intermediate finding; untuk daftar lengkap pakai drill-down `DEFAULT_FBD_DRILLDOWN` [S2].
5. Jalankan search bagian 2.1 sampai 2.4 di tab baru dan tempelkan hasilnya ke note.
6. Ubah Urgency bila konteks membuatnya terlalu rendah (misalnya akun admin terlibat tetapi identity belum terdaftar), lalu pilih Disposition [S2][S4].
7. Eskalasi sesuai matriks bagian 1.7: assign ke L2 atau pindahkan ke team queue L2 bila PT JAB memakainya [S5].

### 2.6 Note tiket SOC-2026-0217

Ini note yang ditulis di tiket sebelum eskalasi, memakai template bagian 1.8. Isinya menjawab pertanyaan kelima SOC lead.

```
[2026-10-14 02:31] Yang dilihat: alert "VPN - login gagal massal dari satu sumber" (>= 100 gagal dari satu src
  dalam 15 menit). src 203.0.113.45, 180 gagal ke 25 akun 01:52-02:06, 1 sukses rina.wulandari 02:04:13.
[2026-10-14 02:38] Yang dicek:
  1) index=vpn src=203.0.113.45 01:30-02:30 -> 181 percobaan, 25 akun, sukses hanya rina.wulandari.
  2) Baseline 30 hari rina.wulandari -> 2 IP Indonesia; 203.0.113.45 first seen 02:04:13 hari ini.
  3) Reputasi -> 203.0.113.45 ada di feed-internal sebagai bruteforce. Identitas -> pemilik juga punya adm.rina.
  4) wineventlog 4624 dari 10.10.250.17 02:04-02:40 -> rina.wulandari ke JKT-FS01 (type 3, 2x),
     adm.rina ke JKT-JUMP01 (type 10, 02:11:02).
[2026-10-14 02:41] Kesimpulan: True Positive - Suspicious Activity, keyakinan tinggi. Kredensial rina.wulandari
  kemungkinan berhasil ditebak; akun admin adm.rina dipakai dari sesi VPN yang sama.
[2026-10-14 02:42] Langkah berikut: eskalasi ke L2 on-call (telepon 02:42, diterima). Rekomendasi: putus sesi VPN
  10.10.250.17, nonaktifkan rina.wulandari dan adm.rina, blokir 203.0.113.45 di gateway VPN. Tindakan oleh L2.
[2026-10-14 02:42] Keterbatasan: belum dicek aktivitas di JKT-JUMP01 setelah 02:11 (Sysmon, PowerShell).
  Rina belum dihubungi lewat telepon (di luar jam kerja). 24 akun lain hanya gagal, belum dicek lockout.
```

**Cara membaca hasil:** setiap klaim di kesimpulan punya baris "yang dicek" dengan rentang waktu dan angka. Analyst lain bisa mengulang search yang sama dan mendapat hasil yang sama.

### 2.7 Handover pukul 07:00

Handover hanya merangkum. Detailnya tetap di tiket.

```
HANDOVER SHIFT MALAM -> PAGI, 2026-10-14 07:00
SOC-2026-0217  In-progress, owner L2 on-call (diambil alih 02:42). True Positive.
  Situasi: kredensial VPN rina.wulandari ditebak dari 203.0.113.45; adm.rina dipakai ke JKT-JUMP01.
  Ditunggu: hasil pemeriksaan JKT-JUMP01 oleh L2; konfirmasi Rina via telepon setelah 08:00.
  Untuk L1 pagi: pantau login gagal dari 203.0.113.0/24 ke VPN; 24 akun lain perlu cek lockout.
SOC-2026-0219  Closed, Benign Positive (change CHG-0912, uji failover RADIUS). Tidak ada tindak lanjut.
```

## 3. Lab praktik

Lab memakai data sintetis dari `makeresults` dan VM Windows lab, tanpa ES. Semua langkah dijalankan di lab terisolasi.

1. **Buat alert sintetis.** Buat 30 event login VPN palsu dengan `makeresults` untuk dilatih:

   ```
   | makeresults count=30
   | streamstats count AS n
   | eval _time=strptime("2026-10-14 01:52:00","%Y-%m-%d %H:%M:%S") + n*30
   | eval src="203.0.113.45", user=case(n%3==0,"andi.pratama", n%3==1,"rina.wulandari", true(),"budi.santoso")
   | eval action=if(n==25,"success","failure")
   | stats count(eval(action="failure")) AS gagal count(eval(action="success")) AS sukses BY user
   ```

   Hitung dulu hasil yang diharapkan sebelum menjalankan: n=1 sampai 30 dibagi rata ke tiga akun (masing-masing 10 event), dan n=25 jatuh ke `rina.wulandari` karena 25 dibagi 3 bersisa 1. Jadi Rina 9 gagal dan 1 sukses, Andi dan Budi masing-masing 10 gagal. Cocokkan dengan keluaran Splunk-mu.
2. **Tulis lima pertanyaan pertama** (bagian 1.2) untuk alert sintetis itu, termasuk sumber jawabannya.
3. **Buat dua lookup kecil** (`lab_identities.csv` dan `lab_ip_reputation.csv`) lewat Settings > Lookups, lalu jalankan pola bagian 2.3 di atas data sintetis.
4. **Tulis delapan skenario singkat** (fiktif) dan beri disposition ES yang tepat beserta alasan dan pemilik tindak lanjutnya. Minimal: pentest resmi, timestamp salah zona waktu, regex detection terlalu luas, login sukses penyerang, uji detection baru, alert tanpa data pendukung, admin menjalankan alat remote management sesuai change, dan satu kasus yang menurutmu harus Undetermined.
5. **Picu alert nyata di lab.** Dari VM Windows lab, lakukan beberapa login gagal lalu satu sukses ke akun lab. Triage dengan search gaya bagian 2.1 dan 2.4 pada `index` lab-mu, lalu tulis note lengkap dengan template bagian 1.8.
6. **Tulis handover** untuk tiga kasus dari langkah 4 dan 5 (satu terbuka, dua tertutup), maksimal lima baris per kasus.
7. **Uji note-mu.** Minta orang lain (atau dirimu besok) membaca note tanpa penjelasan dan mengulang satu search. Bila ia harus bertanya, perbaiki note-nya.

**Hasil yang sebaiknya tersimpan:**
- Keluaran langkah 1 yang cocok dengan hitungan manual.
- Delapan skenario dengan disposition, alasan, dan pemilik tindak lanjut.
- Satu note tiket lengkap dan satu handover.
- Matriks eskalasi versimu sendiri untuk lab atau tempat kerja (tanpa data kerja nyata).

**Variasi tantangan:** jalankan ulang langkah 4 dengan rekan, lalu bandingkan disposisi kalian. Skenario yang hasilnya berbeda adalah kandidat paragraf di panduan disposisi internal.

## 4. Troubleshooting

Tabel ini memuat masalah yang paling sering muncul saat triage. Cari gejala di kolom pertama.

| Gejala | Kemungkinan penyebab | Cara memeriksa atau memperbaiki |
|---|---|---|
| Finding yang dicari tidak ada di analyst queue | Jendela default 24 jam [S3] atau filter view | Ubah filter waktu, pakai view "All" |
| Banyak finding ditutup Undetermined | Disposition tidak wajib | Aktifkan toggle Required [S1] |
| Urgency rendah padahal akun admin terlibat | Identitas tidak terdaftar di Asset & Identity sehingga priority unknown | Naikkan urgency manual [S4], laporkan celah data identitas |
| Lookup identitas tidak cocok | Format nama akun berbeda (domain prefix, huruf besar) | Normalisasi dengan `lower()` dan buang prefix sebelum lookup |
| `iplocation` kosong | IP privat atau rentang khusus [S8] | Wajar; pakai konteks internal (aset, pool VPN) |
| FP rate per detection tidak berguna | Semua FP diberi satu label | Pakai pembedaan Logic vs Data vs Benign (bagian 1.6) |
| Shift berikutnya bertanya ulang hal yang sama | Note berisi kesan, bukan query dan angka | Pakai template bagian 1.8 |

## 5. Kesalahan umum dan jebakan

- Menutup alert berdasarkan judul atau kebiasaan ("ini biasanya FP") tanpa melihat event aslinya. Ini cara paling cepat membuat false negative [S9].
- Menyamakan Benign Positive dengan False Positive. Benign Positive berarti detection benar dan aktivitasnya sah [S1]; mencatatnya sebagai FP mendorong detection engineer melemahkan rule yang sudah benar.
- Mencampur FP karena logika dan FP karena data. Tiket tuning jatuh ke orang yang salah dan tidak dikerjakan.
- Menutup finding dengan disposition Undetermined. Itu nilai default yang berarti belum ada disposisi valid [S1], bukan kesimpulan.
- Mengira mengisi disposition otomatis menutup finding. Disposition tidak mengubah status [S1]; kamu tetap harus mengubah status.
- Menerima "itu saya" dari pengguna lewat chat akun yang sama sebagai bukti tunggal. Kanal itu bisa dikuasai penyerang; pakai kanal kedua.
- Tidak eskalasi karena takut dianggap tidak mampu. Ketidakpastian adalah alasan eskalasi yang sah, dan eskalasi dengan note yang baik justru menghemat waktu L2.
- Mengambil tindakan containment sendiri (menonaktifkan akun, memblokir IP pelanggan) di luar wewenang L1. Rekomendasikan di note, biarkan L2 atau pemilik sistem yang memutuskan.
- Mengandalkan urgency ES tanpa melihat isi. Urgency dihitung dari severity dan priority aset atau identitas [S4]; bila data Asset & Identity tidak lengkap, urgency ikut keliru.
- Menghapus kasus yang sudah dieskalasi dari handover sebelum L2 mengonfirmasi pengambilalihan.

## 6. Catatan terkini

Bagian ini menampung detail versi dan istilah yang berubah. Isinya tidak mengubah alur triage, tetapi menjelaskan kenapa dokumentasi lama memakai nama lain.

- Di ES 8, notable event menjadi finding dan Incident Review menjadi analyst queue di Mission Control. Artikel Lantern tentang alur kerja insiden [S6] masih memakai istilah ES 7 (Incident Review, investigation workbench), sehingga nama menu di sana tidak sama dengan ES 8.7.
- Dokumentasi ES 8.7 menyebut tujuh disposition di drop-down Disposition, tetapi daftar di panel Configure > Findings and investigations > Dispositions hanya menampilkan lima (tanpa Other dan Testing) [S1]. Cek tampilan di instance ES-mu bila admin menambah disposition kustom.
- Dokumentasi ES 8.7 menyebut contoh status seperti New, In-progress, Resolved, dan Closed [S1][S3]. Daftar persisnya bisa berbeda per deployment, jadi cek di instance-mu.
- Pengaturan izin queue default dapat diubah mulai ES 8.6 [S5].
- Splunk Enterprise 10.6 menyertakan database geolokasi `dbip-city-lite.mmdb` (DB-IP) untuk `iplocation`; database GeoLite2-City atau GeoIP2-City bisa diunggah lewat Splunk Web sebagai pengganti [S8]. Hasil lokasi bisa berbeda antar database.
- Microsoft Sentinel memakai klasifikasi penutupan yang sejajar dengan ES (true positive, benign positive, dua jenis false positive, undetermined) dan mewajibkan klasifikasi saat menutup incident [S10]. Berguna bila kamu pindah platform atau membaca laporan tim lain.

## 7. Cheat sheet

```
ALUR      ambil alih (owner, In-progress) -> 5 pertanyaan -> enrichment -> disposisi / eskalasi -> note -> handover
5 TANYA   siapa | apa | di mana | kapan | apakah wajar (baseline, change, pentest)
LANTERN   Review events (finding, alert terjadwal, email, tiket) -> Assessment (abaikan? tunda? tutup? prioritaskan)
DISPOSISI detection benar? + aktivitas berbahaya?
  TP          ya + ya          -> eskalasi L2
  Benign      ya + tidak (sah) -> tutup, pengecualian sempit bila perlu, rule TIDAK diubah
  FP-Logic    tidak + tidak    -> tiket tuning ke detection engineer
  FP-Data     tidak + tidak    -> tiket ke data/platform (add-on, parsing, zona waktu)
  Undetermined belum tahu      -> JANGAN ditutup; eskalasi/tunda dengan alasan
ES 8.7    7 label: Undetermined (default) | TP - Suspicious Activity | Benign Positive - Suspicious But Expected
          | FP - Incorrect Analytic Logic | FP - Inaccurate Data | Other | Testing
          Configure > Findings and investigations > Dispositions ; Required ; +Disposition
          disposition != status ; urgency = severity detection x priority aset/identitas
ESKALASI  dampak (admin, svc, aset kritis) | wewenang (containment) | ketidakpastian
NOTE      Yang dilihat | Yang dicek (query + rentang + angka) | Kesimpulan + keyakinan | Langkah berikut | Keterbatasan
SPL       stats count dc(user) values(action) min(_time) max(_time) BY src
          stats count(eval(action="failure")) AS gagal count(eval(action="success")) AS sukses BY user
          lookup <tabel> <kolom> AS <field> OUTPUT|OUTPUTNEW ... ; iplocation src (IP privat = kosong)
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Vendor pentest resmi PT JAB menjalankan password spraying ke VPN sesuai jadwal change. Alert "login gagal massal" menyala, dan rekanmu menutupnya sebagai False Positive - Incorrect Analytic Logic. Tepat?

<details><summary>Jawaban</summary>

Tidak. Detection bekerja benar dan aktivitasnya nyata, hanya saja sah dan diharapkan, jadi disposisinya Benign Positive - Suspicious But Expected. False Positive - Incorrect Analytic Logic berarti logika detection salah dan harus diperbaiki; label itu akan mengirim detection engineer untuk melemahkan rule yang sebenarnya sudah benar. Bukti yang perlu ditulis di note adalah nomor change atau jadwal pentest, dan tindak lanjut paling jauh adalah pengecualian sempit dan berbatas waktu. Lihat bagian 1.4 dan 1.6.

</details>

**2. Skenario keputusan.** Pada SOC-2026-0217, kamu sudah melihat login sukses `rina.wulandari` dari `203.0.113.45` dan logon `adm.rina` ke `JKT-JUMP01` dari IP VPN yang sama. Rina mengirim chat dari akunnya: "Itu saya kok, lagi coba VPN dari luar." Apa langkah yang paling tepat?

- A. Tutup sebagai Benign Positive karena pengguna sudah mengonfirmasi.
- B. Beri disposisi True Positive, eskalasi segera ke L2 on-call dengan note lengkap dan rekomendasi tindakan, dan catat bahwa konfirmasi lewat chat belum diverifikasi lewat kanal kedua.
- C. Nonaktifkan sendiri kedua akun Rina, blokir IP-nya, lalu tutup tiket sebagai True Positive.

<details><summary>Jawaban</summary>

B. Akun admin terlibat dan ada login sukses setelah rangkaian gagal dari sumber tak dikenal, dua kondisi yang menurut matriks eskalasi PT JAB harus dieskalasi segera. A keliru karena chat dari akun yang sama bisa berasal dari penyerang; konfirmasi pengguna harus lewat kanal kedua dan hanya bukti pendukung, apalagi IP itu dikenal sebagai sumber brute force dan 24 akun lain juga dicoba. C keliru karena menonaktifkan akun dan memblokir IP adalah tindakan di luar wewenang L1, dan menutup tiket menghentikan scoping yang belum dilakukan. Lihat bagian 1.2, 1.7, dan 2.4.

</details>

**3. Pertanyaan jebakan.** "Undetermined itu disposisi yang aman untuk menutup finding kalau kita ragu." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Undetermined adalah nilai default yang berarti finding belum punya disposisi yang valid. Kalau kamu ragu, itu alasan untuk eskalasi atau menunda dengan alasan tertulis, bukan untuk menutup. Admin ES bisa mengaktifkan toggle Required supaya finding tidak bisa ditutup tanpa disposisi. Finding yang ditutup Undetermined juga merusak metrik FP rate per detection. Lihat bagian 1.5 dan 1.6.

</details>

**4. Jelaskan ulang.** Jelaskan kepada detection engineer PT JAB dalam tiga kalimat beda Benign Positive, False Positive - Incorrect Analytic Logic, dan False Positive - Inaccurate Data, termasuk apa yang harus ia lakukan untuk masing-masing.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Benign Positive berarti rule-mu benar dan aktivitasnya nyata, tetapi sah, seperti pentest terjadwal, jadi rule-nya jangan diubah; paling jauh tambahkan pengecualian sempit yang berbatas waktu. False Positive - Incorrect Analytic Logic berarti rule-mu menangkap sesuatu di luar tujuannya, misalnya menghitung session timeout sebagai login gagal, dan itu tiket tuning untukmu. False Positive - Inaccurate Data berarti rule-nya benar tetapi datanya salah, misalnya zona waktu atau parsing, jadi tiketnya ke pengelola add-on dan onboarding, bukan ke kamu."

Kesalahan yang sering muncul:
- Menganggap Benign Positive sebagai jenis false positive.
- Mengirim semua FP ke detection engineer, termasuk yang penyebabnya data.
- Tidak menyebut bukti yang harus ada di note untuk masing-masing disposisi.

</details>

**5. Skenario keputusan.** Pukul 06:50, SOC-2026-0217 sudah diambil alih L2 on-call tetapi masih In-progress. Apa yang kamu tulis di handover pukul 07:00?

- A. Tidak perlu dimasukkan, karena kasus sudah di tangan L2.
- B. Salin seluruh note tiket ke handover supaya shift pagi tahu semuanya.
- C. Satu entri ringkas: nomor tiket, status dan owner, satu kalimat situasi, hal yang ditunggu, dan pekerjaan L1 pagi (misalnya pantau login dari 203.0.113.0/24 dan cek lockout 24 akun lain).

<details><summary>Jawaban</summary>

C. Handover adalah ringkasan kasus yang masih terbuka; detailnya tetap di tiket. A keliru karena kasus yang dieskalasi tetap masuk handover sampai L2 mengonfirmasi pengambilalihan, dan shift pagi tetap punya tugas pemantauan. B keliru karena handover yang berisi salinan note penuh justru menyembunyikan hal yang ditunggu dan tugas yang harus dikerjakan. Lihat bagian 1.8 dan 2.7.

</details>

**6. Pertanyaan jebakan.** "Begitu aku memilih True Positive di drop-down Disposition dan menyimpan, finding otomatis berstatus Closed." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Di ES, disposition dan status adalah field terpisah, dan mengisi disposition tidak mengubah status finding. Status menjawab posisi kasus dalam alur kerja, disposition menjawab hasil penilaian. Finding True Positive yang dieskalasi justru biasanya tetap In-progress di tangan L2. Lihat bagian 1.5.

</details>

**7. Interview question (English).** "Walk me through how you triage an alert as a tier 1 analyst."

<details><summary>Sample answer</summary>

"First I take ownership and set the status so nobody duplicates the work, and I read the detection logic so I know what the alert is actually counting. Then I go to the raw events and answer who, what, where, when, and whether it's normal for that user or host, using a baseline and the change calendar. I enrich with asset and identity context and reputation, because the same login looks very different if the user also owns an admin account. Then I decide: true positive goes to tier 2 straight away, benign positive gets closed with the evidence that it was authorised, false positives are split into logic or data problems so the right team fixes them, and if I can't prove any of those I escalate as undetermined instead of closing it. Whatever I decide, my ticket note lists what I saw, what I checked with the exact query and time range, my conclusion with confidence, the next step and owner, and what I couldn't check, so the next shift or tier 2 can pick it up without asking me."

What makes this answer strong: it shows a repeatable sequence, distinguishes benign positives from the two kinds of false positive and explains why that matters, treats uncertainty as a reason to escalate, and ends with documentation that someone else can act on.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | ES 8.7: Configure dispositions for findings in Splunk Enterprise Security | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/investigations/configure-dispositions-for-findings-in-splunk-enterprise-security | primer | diakses 2026-10-14 | Tinggi. Tujuh disposition, default Undetermined, Required, disposition kustom, disposition tidak mengubah status |
| S2 | ES 8.7: Triage findings and finding groups in Splunk Enterprise Security | https://help.splunk.com/en/splunk-enterprise-security-8/user-guide/8.7/mission-control/triage-findings-and-finding-groups-in-splunk-enterprise-security | primer | diakses 2026-10-14 | Tinggi. Langkah triage, note wajib, batas 100 finding di finding group |
| S3 | ES 8.7: Sort and filter findings and investigations for triage in Splunk Enterprise Security | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/mission-control/sort-and-filter-findings-and-investigations-for-triage-in-splunk-enterprise-security | primer | diakses 2026-10-14 | Tinggi. Jendela default 24 jam, view Unassigned, contoh status |
| S4 | ES 8.7: Configure the urgency for findings in Splunk Enterprise Security | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/findings/configure-the-urgency-for-findings-in-splunk-enterprise-security | primer | diakses 2026-10-14 | Tinggi untuk prinsip perhitungan. Tabel matriks di halaman tampak memuat baris berulang, jadi hanya contoh yang konsisten yang dipakai |
| S5 | ES 8.7: Analyst and team-based queues in Splunk Enterprise Security | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/mission-control/analyst-and-team-based-queues-in-splunk-enterprise-security | primer | diakses 2026-10-14 | Tinggi. Queue default, kondisi queue, batasan routing finding group |
| S6 | Splunk Lantern: Creating an incident workflow in Splunk Enterprise Security | https://lantern.splunk.com/Security_Use_Cases/Advanced_Threat_Detection/Creating_an_incident_workflow_in_Splunk_Enterprise_Security | primer | tanggal tidak terlihat; diakses 2026-10-14 | Tinggi untuk tahap Review events dan Assessment, note, dan handoff. Memakai istilah ES 7 |
| S7 | Splunk Enterprise 10.6 Search Reference: lookup | https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.6/search-commands/lookup | primer | diakses 2026-10-14 | Tinggi. OUTPUT vs OUTPUTNEW |
| S8 | Splunk Enterprise 10.6 Search Reference: iplocation | https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.6/search-commands/iplocation | primer | diakses 2026-10-14 | Tinggi. Field output, IP privat, database bawaan |
| S9 | Splunk blog: SOC Metrics: Security Metrics & KPIs for Measuring SOC Success | https://www.splunk.com/en_us/blog/learn/security-operations-metrics.html | primer (vendor) | 2023-05-18; diakses 2026-10-14 | Tinggi untuk definisi FP rate dan FN rate |
| S10 | Microsoft Learn: Basic incident tasks for Microsoft Sentinel incidents in the Azure portal | https://learn.microsoft.com/en-in/azUre/sentinel/incident-navigate-triage | primer (vendor lain) | ms.date 2026-07-02; diakses 2026-10-14 | Tinggi. Pembanding: lima klasifikasi penutupan yang sejajar dengan ES |

**Catatan sumber:** matriks eskalasi di bagian 1.7, template note di bagian 1.8, dan kriteria bukti minimum di bagian 1.6 adalah praktik kerja yang disusun untuk catatan ini, bukan aturan produk. Halaman urgency ES 8.7 [S4] memuat tabel matriks yang tampak berulang di beberapa baris; catatan ini hanya memakai prinsip perhitungan dan dua contoh yang konsisten, jadi cek matriks lengkapnya di dokumentasi sebelum mengutip angka per sel. Nama field finding di ES 8.7 untuk query metrik disposisi tidak dibahas di sini (lihat Day 34).
