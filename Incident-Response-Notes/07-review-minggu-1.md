---
day: 07
title: 'Review Minggu 1: siklus IR dari declare sampai akhir recovery, peta konsep, glosarium, dan lab gabungan'
researched_on: 2026-10-15
versions_checked: 'NIST SP 800-61 Rev. 3 (April 2025); NIST SP 800-61 Rev. 2 (Agustus 2012, withdrawn 3 April 2025); SANS Incident Handler''s Handbook (Kral, 21 Februari 2012); CISA Cybersecurity Incident and Vulnerability Response Playbooks (November 2021); CISA AA20-245A (1 September 2020, revisi 24 September 2020); RFC 3227 (BCP 55, Februari 2002); NIST SP 800-86 (Agustus 2006); NCSC UK Recovering from a highly disruptive cyber attack, Section 2 (terbit 28 Juli 2026, direview 1 Oktober 2026); Mandiant M-Trends 2026 (24 Maret 2026); dokumentasi Microsoft yang dirujuk Day 05 dan Day 06 (ms.date 2025-05-21 sampai 2026-07-23)'
---

# Day 07: Review Minggu 1, siklus IR dari declare sampai akhir recovery

Cakupan: ringkasan Day 01-06 (siklus dan peran, IR plan dan eskalasi, scoping, pengamanan bukti, containment, eradication dan recovery), peta konsep satu insiden dari alert pertama sampai pernyataan akhir recovery, tiga benang yang ditelusuri lewat `INC-2026-019`, glosarium, dan lab gabungan berupa paket IR, tabletop mini, dan uji lisan.

## Ide inti

Day 01-06 bukan enam topik terpisah, tetapi satu rantai keputusan. Setiap tahap punya tiga hal yang ditulis sebelum malam insiden: siapa yang memutuskan, artefak apa yang dihasilkan, dan kriteria apa yang membuat tahap itu boleh dianggap selesai. Declare punya kriteria insiden, scoping punya syarat minimal sebelum containment, bukti punya urutan dan evidence log, containment punya kriteria berhasil, dan recovery punya kriteria akhir. Rantai ini juga tidak lurus. Temuan baru di tahap mana pun bisa mengembalikan insiden ke scoping, dan itu tanda proses bekerja, bukan gagal. Kemampuan IR terlihat dari bisa menceritakan satu insiden dengan cara itu: di mana setiap tahap mulai dan berakhir, siapa yang memutuskan, bukti apa yang membuatnya boleh berakhir, dan kapan serta kenapa insiden mundur ke tahap sebelumnya.

Kamu sudah mengenal rantai ini dari gangguan besar di NOC. Gangguan dinyatakan dan bridge dibuka, sebarannya dicek POP demi POP, `show tech` diambil sebelum perangkat di-reboot, trafik dialihkan dulu, modul rusak diganti setelah penyebabnya diketahui, layanan dipulihkan lalu dipantau ketat, dan RFO ditulis. IR memakai alur yang sama dengan dua perbedaan yang sudah muncul berkali-kali sepanjang minggu ini. Pertama, tahapnya berulang dan tumpang tindih: scoping baru bisa membuka containment lagi, dan analisis bukti bisa membatalkan rencana clean. Kedua, lawannya manusia yang bisa melihat respons kita, sehingga urutan dan waktu tindakan ikut menentukan hasil.

```
alert ---> DECLARE (Day 01)          kriteria insiden | catatan declare | IC, severity
              |
              v
          SCOPING (Day 03)  <--------------------------------------+
              |  kartu jam pertama, hipotesis, pivot, scope statement |
              |  keluar bila: host C2, akun/kredensial, persistence,  |
              |               batas visibilitas diketahui             |
              v                                                       |
          BUKTI (Day 04)          urutan volatilitas, evidence log,   |
              |                   chain of custody, proporsional      |
              v                                                       |
          CONTAINMENT (Day 05)    memo keputusan, jam H, validasi ----+  host/akun baru
              |  keluar bila: kriteria selesai containment terpenuhi  |
              v                                                       |
          ERADICATION (Day 06)    rebuild/reimage, akar masalah, rotasi
              |                                                       |
              v                                                       |
          RECOVERY (Day 06)       sumber tepercaya, gerbang validasi, |
              |                   cutover, pemantauan  -- tanda baru -+
              |  keluar bila: kriteria akhir recovery terpenuhi
              v
          post-incident review, lalu insiden ditutup

Di semua tahap (Day 01-02): peran, RACI, eskalasi, ritme update, handover, timeline scribe
```

Situasi yang dipakai di Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan dan 400 ribu pelanggan broadband, yang menangani insiden dengan CSIRT virtual. Jumat, 23 Oktober 2026 siang, setelah recovery `INC-2026-019` dinyatakan selesai dan empat hari sebelum post-incident review-nya, SOC lead dan incident commander (IC) Dimas Prasetyo menulis ke analyst L2 Rudi Hartanto, yang minggu depan menjadi primary L2 on-call tetapi belum membaca berkas `INC-2026-019` secara utuh:

> "Rud, minggu depan kamu primary on-call. Tolong pelajari `INC-2026-019` dari alert pertama sampai pernyataan akhir recovery, karena kasus itu menyentuh semua tahap. Senin pagi ceritakan ke saya dalam lima menit tanpa buka catatan. Saya mau dengar: tahap apa saja yang kita lewati, kapan masing-masing mulai dan selesai, dan dokumen apa yang keluar di tiap tahap; siapa yang memutuskan setiap langkah besar dan kenapa bukan orang lain; kenapa severity naik turun; kapan kita sengaja menunda dan kenapa itu bukan kelalaian; dan kapan kita harus mundur ke tahap sebelumnya."

Pesan itu memuat lima permintaan:

1. Tahap yang dilewati, kapan mulai dan selesai, dan artefak tiap tahap.
2. Siapa yang memutuskan setiap langkah besar, dan kenapa.
3. Kenapa severity naik dan turun.
4. Kapan penanganan sengaja ditunda, dan kenapa itu bukan kelalaian.
5. Kapan dan kenapa insiden mundur ke tahap sebelumnya.

Permintaan 1 dijawab di bagian 1.8, permintaan 2 dan 3 di bagian 1.9, serta permintaan 4 dan 5 di bagian 1.10. Bagian 1.1 sampai 1.6 meringkas Day 01-06 sebagai bahannya, dan bagian 2-4 memintamu melakukan hal yang sama untuk insiden lain.

**Kapan relevan:** sebelum masuk Day 08 dan seterusnya (setiap jenis insiden di minggu berikutnya memakai rantai yang sama), sebelum pertama kali masuk jadwal on-call atau memegang peran IC, dan sebelum interview yang meminta kamu menceritakan satu insiden dari awal sampai akhir.
**Kapan bukan jawaban:** review ini tidak menambah aturan baru. Bila ada yang terasa baru, kembali ke Day asalnya. Review ini juga bukan post-incident review: format review setelah insiden dan laporan akhirnya dibahas tersendiri nanti.

## 1. Ringkasan, peta konsep, dan glosarium

### 1.1 Day 01: gambaran IR, siklus, peran, dan severity

- Triage menjawab "apakah alert ini benar dan apa yang terjadi"; IR menjawab "apa yang dilakukan sekarang, siapa memutuskan, seberapa parah" (Day 01 bagian Ide inti).
- NIST SP 800-61 Rev. 3 memakai tiga lapis: event, adverse event, dan insiden. Insiden adalah kejadian yang membahayakan kerahasiaan, integritas, atau ketersediaan tanpa wewenang, termasuk ancaman yang dekat, atau pelanggaran hukum dan kebijakan. Tidak perlu ada layanan yang turun [S1].
- Declare adalah keputusan tercatat yang menyalakan IR plan, peran, timeline, penjagaan bukti, dan notifikasi (DE.AE-08, RS.MA-01, RS.MA-02) [S1]. Declare tidak menunggu semua pertanyaan terjawab.
- Rev. 2 (Agustus 2012) memakai empat fase dengan panah balik dari containment ke analisis, dan sudah withdrawn sejak 3 April 2025 [S2][S5]. Rev. 3 (April 2025) adalah CSF 2.0 Community Profile dengan model tiga lapis: Govern, Identify, Protect sebagai persiapan; Detect, Respond, Recover sebagai respons; Improvement (ID.IM) di tengah [S1].
- PICERL dari SANS memisahkan containment, eradication, dan recovery menjadi tiga tahap, masing-masing dengan pemilik keputusan dan kriteria selesai sendiri [S6].
- IC mengoordinasi dan memutuskan, tidak mengerjakan teknis; technical lead memimpin analisis; scribe mencatat fakta, keputusan, dan tindak lanjut; executive sponsor memutuskan hal berdampak bisnis besar [S7].
- Severity diturunkan dari dimensi dampak (functional impact, information impact, recoverability) [S2]. Severity insiden berbeda dengan prioritas alert. Aturan PT JAB: ragu pilih lebih tinggi, setiap perubahan dicatat dengan alasan.
- UU 27/2022 Pasal 46 mewajibkan pemberitahuan tertulis paling lambat 3 x 24 jam bila terjadi kegagalan pelindungan data pribadi; titik mulai hitungannya perlu dicek di penjelasan resmi UU dan peraturan pelaksananya [S16][S17].

### 1.2 Day 02: IR plan, RACI, eskalasi, on-call, dan handover

- Tiga lapis dokumen: kebijakan (siapa berwenang), IR plan (bagaimana kemampuan IR diorganisasi), playbook dan prosedur (langkah per jenis insiden). Aturan hanya bisa mengalahkan prosedur lain bila ditulis di lapis yang disetujui orang yang berwenang atas keduanya [S1][S2].
- Wewenang ditulis per tindakan. IC on-call PT JAB punya wewenang di muka untuk blokir IOC, isolasi host, dan disable akun; mematikan layanan pelanggan tetap di executive sponsor [S1][S18].
- RACI: tepat satu A per aktivitas, minimal satu R. Pemilik sistem biasanya R untuk eksekusi, bukan A atas keputusan containment.
- Matriks eskalasi memuat pemicu, kontak, kanal, batas waktu, dan kontak berikutnya. Pemicu keamanan juga berupa jenis data dan jenis akun, bukan hanya durasi atau jumlah pelanggan. Timeout dihitung mundur dari target severity.
- On-call butuh akses yang sudah diuji, kontak luar yang siap, dan batas kelelahan. Handover insiden membawa fakta, hipotesis, keputusan, dan hal yang sengaja belum dilakukan; serah terima IC harus eksplisit dan dikonfirmasi [S7].
- Plan yang tidak diuji gagal di titik yang sama dengan insiden terakhir. PT JAB menguji kontak mingguan, akses kuartalan, dan tabletop minimal sekali setahun (ID.IM) [S1].

### 1.3 Day 03: triage awal dan scoping

- Jam pertama setelah declare menghasilkan jawaban cukup untuk memutuskan langkah berikutnya: yang terkonfirmasi, jenis akses, hak yang dicapai, yang belum diketahui, dan sumber data beserta batasnya [S2][S3].
- Hipotesis ditulis dengan bukti dan cara menguji; hipotesis yang dipatahkan ikut dicatat [S3].
- Pivot IOC, host, akun, dan waktu diulang sampai tidak ada temuan baru. Pivot IOC rapuh karena IOC bisa berbeda per korban. Jangan menyentuh infrastruktur penyerang [S4].
- Alert pertama bukan awal insiden. M-Trends 2026 mencatat median dwell time global 14 hari [S14]; PT JAB memakai jendela awal 30 hari, dibatasi retensi log.
- Blast radius dihitung dari akses dan kredensial yang dipegang penyerang, bukan dari host yang beacon (RS.AN-08) [S1][S3].
- Scope cukup untuk containment bila host C2, akun dan kredensial yang terekspos, jenis persistence, dan batas visibilitas sudah diketahui. Scope statement selalu bertanggal, berversi, dan diberi tingkat keyakinan [S3].

### 1.4 Day 04: live response dan pengamanan bukti

- Containment mengubah keadaan sistem, jadi bukti volatil diambil lebih dulu, kecuali kerusakan sedang berjalan cepat [S4][S9].
- Urutan PT JAB: jam sistem, koneksi, sesi login, memori, proses, file terbuka, konfigurasi jaringan, tmpfs, persistence dan log lokal, lalu log terpusat [S8][S9].
- Windows dengan EDR: paket investigasi dan live response dari portal; memori dengan alat dari media terpercaya. Linux tanpa EDR: SSH dari bastion, toolkit dari media read-only, output tidak ditulis ke disk host, memori dengan AVML atau LiME.
- Jangan restart, full scan, mencabut kabel sendiri, membuka file atau domain C2, login admin domain ke host terdampak, atau memberi instruksi lewat chat korporat [S4][S8].
- Hash membuktikan isi tidak berubah sejak di-hash; evidence log membuktikan apa yang diambil dan bagaimana; chain of custody membuktikan siapa memegang bukti kapan [S2][S8].
- Seberapa jauh pengambilan bukti ditentukan secara proporsional, dan keputusan untuk tidak mengambil bukti tertentu juga dicatat (RS.AN-07) [S1][S9].

### 1.5 Day 05: containment

- Semua containment sementara. Jangka pendek menghentikan penyebaran sekarang; jangka panjang membatasi sambil layanan jalan sampai eradication [S1][S2].
- Strategi dipilih dengan kriteria tertulis: kerusakan, bukti, layanan, waktu dan sumber daya, efektivitas, durasi [S2].
- Menunda untuk bersiap (jam, batas waktu, pemicu) berbeda dengan menunda untuk mengamati (butuh sandbox, Legal, dan executive sponsor) [S1][S2][S3].
- Isolasi host tidak menghentikan kerusakan lokal [S2]. Disable akun tidak langsung mencabut tiket Kerberos [S19] dan token yang sudah terbit [S11], jadi dijalankan bersama reset password dua kali, revoke sessions, dan isolasi host sumber [S11].
- Blok IOC dijalankan di jam H bersama tindakan lain, dengan logging dan DNS sinkhole yang mencatat; blok dini dan reset kredensial dini adalah kesalahan umum [S4].
- Containment serentak di jam H, lalu dinyatakan berhasil hanya bila kriteria tertulis terpenuhi, termasuk periode tanpa tanda baru [S3].

### 1.6 Day 06: eradication dan recovery

- Eradication dimulai setelah containment terbukti: persistence diperhitungkan, aktivitas tertahan, bukti terkumpul [S3].
- Clean hanya menghapus yang ditemukan. Rebuild atau reimage bila penyerang mungkin punya hak tinggi, visibilitas terbatas, persistence lebih dari satu, atau implant interaktif [S3].
- Akar masalah ditutup sebelum sistem pengganti masuk produksi (RC.RP-05) [S1]. Rahasia yang berbentuk akar masalah dicari di semua tempat ia disalin.
- Rotasi mencakup rahasia yang tersimpan, diketik, dan dipasang setelah kompromi. krbtgt hanya direset bila ada bukti kompromi domain, dua kali dengan jeda replikasi [S4][S12][S13].
- Recovery dari sumber tepercaya, berurutan menuju minimum viable operations (MVO), lalu lolos gerbang validasi sebelum cutover [S1][S10].
- Recovery selesai dinyatakan berdasarkan kriteria (RC.RP-06) [S1]; insiden baru ditutup setelah post-incident review.

### 1.7 Peta konsep

Peta berikut menggabungkan diagram Day 01-06 dalam satu gambar. Pakai sebagai satu-satunya bantuan saat uji lisan di bagian 2-4. Kolom kiri adalah tahap, kolom tengah artefak, kolom kanan kriteria keluar.

```
PERSIAPAN (Day 02)   kebijakan > IR plan > RACI, matriks eskalasi, on-call, playbook
                     uji kontak | uji akses | tabletop           (Govern, Identify, Protect)
-------------------------------------------------------------------------------------
TAHAP           ARTEFAK UTAMA                      KRITERIA KELUAR             A
Declare         catatan declare, log aktivasi      kriteria insiden tertulis   IC
  (Day 01)      peran, timeline scribe             terpenuhi; SEV ditetapkan
Scoping         kartu jam pertama, tabel           host C2 + akun/kredensial   IC
  (Day 03)      hipotesis, case notes, scope        + persistence + batas       (scope
                statement vN                        visibilitas diketahui       statement)
Bukti           rencana pengambilan, evidence      volatil aman sebelum jam H; IC
  (Day 04)      log, chain of custody              yang ditunda tercatat
Containment     memo keputusan, rencana jam H,     semua tindakan terverifikasi IC; layanan:
  (Day 05)      query validasi, update status      + 24 jam tanpa tanda baru    exec sponsor
Eradication     rencana eradication+recovery,      rebuild/reimage, akar        IC; layanan
  (Day 06)      inventaris rahasia                 masalah, rotasi selesai      dan pihak
Recovery        gerbang validasi, query pantau,    kriteria akhir recovery      ketiga: exec
  (Day 06)      pernyataan akhir recovery          (termasuk 7 hari tenang)     sponsor
Post-incident   review, laporan, perbaikan         tindak lanjut tercatat       IC (menutup)
-------------------------------------------------------------------------------------
SEPANJANG INSIDEN: severity ditinjau | ritme update sesuai SEV | handover tertulis
                   | temuan baru -> kembali ke scoping | lessons learned dicatat sejak awal
```

Tiga benang dipakai untuk menguji peta ini dengan satu insiden nyata (fiktif):

1. **Benang tahap dan artefak:** setiap tahap punya waktu mulai, waktu selesai, artefak, dan kriteria keluar (bagian 1.8).
2. **Benang keputusan dan severity:** setiap keputusan besar punya satu pemilik sesuai RACI, dan setiap perubahan severity punya alasan (bagian 1.9).
3. **Benang menunda dan mundur:** setiap penundaan punya batas dan pemicu, dan setiap temuan baru mengembalikan insiden ke tahap yang tepat (bagian 1.10).

### 1.8 Benang tahap dan artefak `INC-2026-019`

Tabel berikut menjawab permintaan pertama Dimas. Semua waktu WIB dan semua fakta diambil dari Day 03-06; kolom terakhir menunjuk bagian tempat fakta itu ditulis. Baca per baris: titik akhir satu tahap harus berupa kriteria; jam saja tidak cukup.

| Tahap | Mulai | Artefak utama | Selesai, dan kriteria yang dipakai | Asal |
|---|---|---|---|---|
| Aktivitas penyerang sebelum deteksi | Email diterima 9 mailbox Senin 2026-10-12 15:58; lampiran dibuka Andi 16:05 | (direkonstruksi lewat pivot waktu) | Alert pertama Selasa 09:47, hampir 18 jam kemudian | Day 03 bagian 1.4 dan 2.5 |
| Deteksi dan declare | Alert `SOC-2026-0203` Selasa 09:47 | Validasi Sari 10:30, declare SEV-3 oleh Dimas 10:40 | Kriteria insiden terpenuhi | Day 03 bagian Ide inti |
| Scoping | 10:45 | Kartu jam pertama 10:55, hipotesis H1 sampai H5, case notes, scope statement v1 11:50 dan v2 13:00 | Empat syarat minimal containment terpenuhi di v2; v3 setelah 17:20 | Day 03 bagian 1.6, 2.1, 2.4, 2.5; Day 05 bagian 2.4 |
| Pengamanan bukti | Rencana dikirim 12:25, disetujui 12:28 | Evidence log E01 sampai E12, chain of custody per item | Bukti volatil tiga host aman sebelum jam H; image disk sengaja ditunda ke rebuild | Day 04 bagian 2.1 dan 2.5 |
| Containment | Memo keputusan 14:55, keputusan Hendra 15:10, jam H 16:00 | Memo pilihan A, B, C; rencana jam H; query validasi; update 18:00 | Dinyatakan berhasil Rabu 2026-10-14 17:20, 24 jam setelah host ketiga ditahan | Day 05 bagian 2.1 sampai 2.5; Day 06 bagian 2.2 |
| Eradication | Rabu 17:20 | Hasil awal retainer Rabu 10:00, rencana eradication dan recovery, pencarian salinan kredensial | Rebuild, reimage, rotasi, dan penyebab langsung ditutup | Day 06 bagian 2.1 sampai 2.3 |
| Recovery | Build `jkt-billing02` Rabu 18:00; gerbang validasi Kamis 14:00 sampai 18:00; cutover Kamis 2026-10-15 23:00 | Gerbang validasi, query pemantauan, pernyataan akhir | Dinyatakan selesai Jumat 2026-10-23 10:00 setelah 7 hari tanpa tanda penyerang | Day 06 bagian 2.4 dan 2.5 |
| Post-incident | Selasa 2026-10-27 | Review dan after-action report | Insiden ditutup setelah tindak lanjut tercatat; pemantauan berjalan sampai 2026-11-14 | Day 06 bagian 2.5 |

Tiga hal yang terlihat bila tabel dibaca dari atas ke bawah:

- **Tahap tumpang tindih.** Scoping masih berjalan saat bukti diambil, dan berjalan lagi setelah jam H. Eradication dan recovery dikerjakan bersama: `jkt-billing02` dibangun sementara laptop di-reimage. Ini sesuai panah balik di Rev. 2 dan catatan playbook CISA bahwa eradication dan recovery bisa berjalan bersamaan [S2][S3].
- **Setiap tahap meninggalkan artefak yang dipakai tahap berikutnya.** Scope statement v1 menjadi dasar rencana bukti dan v2 menjadi dasar memo containment; evidence log menjadi dasar analisis retainer; analisis retainer menjadi dasar keputusan rebuild dan pelaporan DPO.
- **Selesai selalu berarti kriteria.** Containment "berjalan" pukul 16:12, tetapi "berhasil" baru Rabu 17:20. Layanan "pulih" Kamis 23:00, tetapi recovery "selesai" baru Jumat 2026-10-23.

### 1.9 Benang keputusan dan severity

Permintaan kedua Dimas dijawab dengan mencocokkan setiap keputusan besar ke RACI PT JAB (Day 02 bagian 2.2). Tabel berikut berisi keputusan yang paling sering ditanyakan; perhatikan kolom "Kenapa bukan orang lain", karena di situ salah paham soal peran biasanya muncul.

| Keputusan | Waktu | Diputuskan oleh | Kenapa bukan orang lain |
|---|---|---|---|
| Declare `INC-2026-019` SEV-3 | Selasa 10:40 | Dimas (IC), atas validasi Sari | L2 memvalidasi dan mengusulkan (R), IC menyatakan (A) |
| Tidak mengisolasi laptop Andi pagi itu | 10:45 | Dimas (IC) | Keputusan containment ada di IC, berdasarkan rekomendasi technical lead |
| Mengaktifkan retainer | 13:35 | Dimas (IC) | Dalam kuota kontrak, IC adalah A/R; di luar kuota menjadi keputusan Direktur Teknologi |
| Containment parsial `jkt-billing01` (pilihan B), maksimal 72 jam | 15:10 | Hendra (executive sponsor) | Mematikan atau membatasi layanan pelanggan adalah keputusan bisnis; IC hanya C |
| Delegasi bersyarat untuk mematikan `jkt-billing01` | 15:10 | Hendra, didelegasikan tertulis ke IC | Keputusan bisnis yang diambil di muka, dengan pemicu tertulis |
| Isolasi laptop, blok C2, sinkhole, disable akun di jam H | 16:00 | Dimas (IC) | Wewenang di muka IC; NOC dan Infrastruktur adalah R |
| Rotasi `billing_app` yang menghentikan portal sekitar 10 menit | 16:02 sampai 16:11 | Hendra | Dampak layanan pelanggan, walaupun sudah diputuskan di memo |
| Containment berhasil dan severity turun ke SEV-2 | Rabu 17:20 | Dimas (IC) | IC menetapkan severity dan menilai kriteria |
| Rotasi kunci API payment gateway dan cutover ke `jkt-billing02` | Kamis | Hendra | Melibatkan pihak ketiga dan layanan pelanggan |
| Recovery selesai | Jumat 2026-10-23 10:00 | Dimas (IC) | IC menilai kriteria; menutup insiden juga A IC, setelah post-incident review |

Permintaan ketiga Dimas ("kenapa severity naik turun") dijawab oleh jalur berikut. Setiap perubahan punya alasan yang bisa diperiksa terhadap kriteria SEV PT JAB (Day 01 bagian 1.7).

| Waktu | Severity | Alasan tertulis | Asal |
|---|---|---|---|
| Selasa 10:40 | SEV-3 | Satu endpoint dan akun biasa, belum ada tanda penyebaran | Day 03 bagian Ide inti |
| Selasa 11:50 | SEV-2 | Sistem kritis `jkt-billing01` terkompromi, akun service `svc_billing` disalahgunakan, data pribadi mungkin terdampak | Day 03 bagian 2.4 |
| Selasa 13:35 | SEV-1 | `kworkerd` terhubung ke database pelanggan dan log database hanya mencatat koneksi, sehingga akses ke data tidak bisa disingkirkan; aturan ragu pilih lebih tinggi | Day 04 bagian 2.3; Day 05 bagian Ide inti |
| Rabu 17:20 | SEV-2 | Akses penyerang yang diketahui tertutup dan terverifikasi 24 jam, tidak ada kerusakan berjalan, dampak data ditangani jalur pelaporan DPO | Day 06 bagian 2.2 |

Dua pelajaran dari jalur ini. Pertama, kenaikan severity selalu mengikuti blast radius, bukan jumlah host: dari satu laptop ke SEV-2 terjadi karena kredensial `svc_billing`, bukan karena host kedua. Kedua, penurunan ke SEV-2 tidak berarti dampaknya kecil. Analisis retainer menyebut 5.000 baris data pelanggan kemungkinan besar diambil, dan kesimpulan itu diteruskan ke DPO dan Legal Rabu 10:20 (Day 06 bagian 2.1). Severity mengatur siapa terlibat dan ritme update respons; kewajiban atas data berjalan di jalurnya sendiri.

### 1.10 Benang menunda dan mundur

Permintaan keempat dan kelima Dimas adalah bagian yang paling sering disalahpahami orang di luar tim. Tabel pertama berisi penundaan yang disengaja. Baca kolom "Batas dan pemicu": penundaan tanpa keduanya adalah kelalaian.

| Yang ditunda | Kenapa | Batas dan pemicu | Asal |
|---|---|---|---|
| Isolasi, reset password, dan blok C2 sejak 10:45 | Scope belum diketahui; tindakan dini memberi tahu penyerang dan menghilangkan visibilitas | Jam H 16:00; pemicu containment segera ditulis di rencana bukti sejak 12:30 | Day 03 bagian 2.1; Day 04 bagian 2.1; Day 05 bagian 1.3 |
| Image disk ketiga host | Tidak mengganggu layanan; memori dan artefak volatil sudah aman | Diambil saat host keluar dari produksi (E15 sampai E18) | Day 04 bagian 2.1; Day 06 bagian 2.2 |
| Purge email dari 9 mailbox | Menunggu ekspor email asli sebagai bukti | Jam H, setelah ekspor E10 | Day 04 bagian 2.1; Day 05 bagian 2.2 |
| Rebuild `jkt-billing01` | Layanan pembayaran harus jalan; containment parsial dipilih | Maksimal 72 jam; cutover di jam ke-55 | Day 05 bagian 2.1; Day 06 bagian 2.2 |
| Mengamati penyerang 24 jam (usulan retainer) | Tidak ditunda, ditolak: data pribadi, tidak ada sandbox, risiko hukum | Pilihan C di memo, dicatat beserta alasan penolakan | Day 05 bagian 1.3 dan 2.1 |
| Reset krbtgt | Tidak dimasukkan rencana: tidak ada bukti kompromi domain | Pemicu tertulis yang akan mengubah keputusan | Day 06 bagian 1.4 |

Tabel kedua berisi titik ketika insiden mundur ke tahap sebelumnya. Setiap baris adalah contoh panah balik di peta konsep bagian 1.7.

| Temuan | Tahap saat ditemukan | Mundur ke | Akibat | Asal |
|---|---|---|---|---|
| `10.20.5.21` (`jkt-billing01`) beacon ke C2, 11:05 | Scoping awal | Pivot baru dari host dan akun | Blast radius dari satu laptop ke server billing; SEV-2 | Day 03 bagian 2.5 |
| Koneksi `kworkerd` ke `jkt-billingdb01:5432`, saat live response | Pengambilan bukti | Penilaian severity dan dampak | SEV-1 13:35; retainer diaktifkan | Day 04 bagian 2.3 |
| `JKT-WS-0412` muncul di log sinkhole 17:12 | Validasi containment | Scoping dan containment | Host ditahan 17:20, bukti diambil 17:45, scope v3, hitungan 24 jam diulang dari 17:20 | Day 05 bagian 2.4 |
| Salinan kedua implant di `/var/tmp/.font-unix` | Analisis bukti oleh retainer | Keputusan eradication | Clean tidak cukup; rebuild `jkt-billing01` | Day 06 bagian 2.1 |
| `SOC-2026-0204`: login password `svc_billing` ditolak dari `10.10.23.41` | Periode 24 jam containment | Scoping akar masalah | Skrip berisi password ditemukan juga di laptop lain dan share; dijelaskan sebagai pengguna sah | Day 06 bagian 2.3 |
| `SOC-2026-0205`: koneksi NTP ke luar dari `jkt-billing02` | Pemantauan pasca pemulihan | Perbaikan gold image | Dijelaskan sebagai konfigurasi; tidak memundurkan hitungan 7 hari | Day 06 bagian 2.4 |

Pola yang sama muncul di setiap baris: temuan tidak disembunyikan supaya tahap terlihat mulus, tetapi dipakai untuk memperbarui scope dan keputusan. Dua baris terakhir menunjukkan sisi sebaliknya: alert yang bisa dijelaskan dengan bukti tidak memundurkan tahap, asalkan penjelasannya tertulis.

### 1.11 Glosarium

Definisi di bawah ditulis dengan kata sendiri untuk keperluan belajar, bukan definisi resmi. Kolom terakhir adalah pasangan yang paling sering membuat jawaban interview keliru.

| Istilah | Penjelasan singkat | Sering tertukar dengan |
|---|---|---|
| Event | Kejadian apa pun yang bisa diamati pada aset | Alert |
| Alert | Pemberitahuan dari alat deteksi bahwa ada event yang perlu dilihat | Insiden |
| Adverse event | Event berdampak negatif, apa pun penyebabnya | Insiden yang sudah dinyatakan |
| Insiden | Kejadian yang membahayakan CIA tanpa wewenang, ancaman yang dekat, atau pelanggaran hukum dan kebijakan | Gangguan layanan |
| Declare | Keputusan tercatat bahwa sebuah kejadian adalah insiden | Membuka tiket |
| Severity insiden | Tingkat keparahan bagi organisasi, ditetapkan IC dari dimensi dampak | Prioritas alert dari rule |
| Incident commander (IC) | Pemimpin koordinasi dan keputusan respons, tidak mengerjakan teknis | Technical lead, atau orang paling senior di bridge |
| Executive sponsor | Pimpinan yang memutuskan tindakan berdampak bisnis besar | IC |
| Scribe | Pencatat timeline, keputusan, dan tindak lanjut | Penulis case notes teknis |
| Kebijakan IR | Pernyataan wewenang dan definisi, disetujui direksi | IR plan |
| IR plan | Dokumen yang mengorganisasi peran, severity, eskalasi, komunikasi, dan pengujian | Playbook |
| Playbook | Langkah kerja per jenis insiden | IR plan (yang menetapkan siapa boleh) |
| RACI | Pembagian R, A, C, I per aktivitas; tepat satu A | Daftar kontak |
| Wewenang di muka | Izin tertulis untuk tindakan tertentu tanpa persetujuan rutin | Wewenang tak terbatas |
| Escalation dan elevation | Menambah sumber daya vs melibatkan manajemen lebih tinggi | Satu istilah yang sama |
| Handover | Serah terima konteks insiden antar shift | Status tiket |
| Serah terima IC | Pemindahan komando yang eksplisit dan dikonfirmasi | Kedatangan orang yang lebih senior |
| Kanal out-of-band | Jalur komunikasi di luar email dan chat korporat | Grup chat biasa |
| Scoping | Menentukan host, akun, waktu, jalur, dan data yang terlibat | Pencarian IOC saja |
| Hipotesis | Dugaan yang bisa diuji, dengan bukti dan status | Fakta |
| Pivot | Memakai satu temuan untuk mencari temuan berikutnya | Menyelidiki infrastruktur penyerang |
| Dwell time | Selisih awal aktivitas penyerang dan deteksinya | Waktu respons |
| Blast radius | Semua yang bisa dijangkau dari akses penyerang | Jumlah host yang beacon |
| Scope statement | Pernyataan cakupan bertanggal dengan keyakinan dan batas visibilitas | Laporan akhir |
| Case notes | Catatan kerja teknis yang bisa diulang orang lain | Timeline scribe |
| Order of volatility | Urutan pengambilan dari yang paling cepat hilang | Urutan pentingnya data |
| Live response | Pengambilan data dari sistem yang masih menyala | Analisis forensik |
| Hash | Bukti isi file tidak berubah sejak di-hash | Bukti cara pengambilan benar |
| Evidence log | Daftar bukti: apa, dari mana, kapan, oleh siapa, di mana | Chain of custody |
| Chain of custody | Catatan setiap perpindahan bukti antar orang dan tempat | Evidence log |
| Containment jangka pendek | Tindakan cepat menghentikan penyebaran | Solusi permanen |
| Containment jangka panjang | Pembatasan sementara sambil layanan jalan sampai eradication | Eradication |
| Menunda untuk bersiap | Penundaan berjam-jam dengan batas dan pemicu | Menunda untuk mengamati penyerang |
| Tipping off | Penyerang sadar ia terdeteksi karena tindakan responder | Penyerang yang kebetulan berpindah |
| DNS sinkhole | Domain berbahaya diarahkan ke IP pencatat di resolver internal | Blok DNS tanpa logging |
| Jam H | Waktu tindakan containment dijalankan serentak | Waktu IOC ditemukan |
| Kriteria selesai containment | Syarat tertulis sebelum containment dinyatakan berhasil | Semua tindakan sudah diperintahkan |
| Clean | Menghapus artefak yang diketahui dari host yang tetap dipakai | Rebuild |
| Rebuild dan reimage | Membangun ulang host dari sumber bersih | Restore dari backup host lama |
| Gold image | Image standar yang integritasnya diverifikasi | Backup terbaru |
| Akar masalah | Kondisi yang memungkinkan insiden, termasuk proses | Malware yang ditemukan |
| Rotasi rahasia | Mengganti semua rahasia yang pernah terlihat penyerang | Reset password akun pengguna saja |
| krbtgt | Akun yang kuncinya menandatangani tiket Kerberos domain | Akun admin domain |
| Golden ticket | Tiket Kerberos palsu dari kunci krbtgt curian | Tiket yang dicuri dari memori |
| MVO | Tingkat operasi terendah yang aman dan memenuhi kewajiban | Pemulihan penuh |
| Gerbang validasi | Daftar cek berbukti sebelum cutover | Uji fungsi aplikasi saja |
| Recovery selesai | Kriteria akhir recovery terpenuhi | Insiden ditutup |

## 2-4. Lab gabungan dan troubleshooting

Lab ini merapikan latihan Day 01-06 menjadi satu paket, lalu mengujinya dengan tabletop mini dan uji lisan. Semua dikerjakan sebagai dokumen untuk PT JAB. Jangan memakai data, nama, atau kejadian dari pekerjaan nyata.

### Bagian A: timeline terpadu `INC-2026-019`

Gabungkan semua waktu di Day 03-06 menjadi satu timeline dengan kolom berikut. Baris pertama sampai ketiga diberikan sebagai contoh bentuk.

```
Waktu (WIB)       | Tahap       | Jenis      | Isi                                         | A / oleh  | Artefak         | Asal
Sen 12-10 15:58   | sebelum     | FAKTA      | email lampiran diterima 9 mailbox           | -         | message trace   | Day 03
Sel 13-10 09:47   | deteksi     | FAKTA      | alert SOC-2026-0203 di JKT-WS-0388          | EDR       | alert           | Day 03
Sel 13-10 10:40   | declare     | KEPUTUSAN  | declare SEV-3                               | Dimas     | timeline scribe | Day 03
...
```

Setelah lengkap, jalankan tiga pengecekan:

- Setiap baris KEPUTUSAN punya satu nama di kolom A, dan nama itu cocok dengan RACI Day 02 bagian 2.2.
- Setiap perubahan severity punya alasan yang cocok dengan tabel SEV di Day 01 bagian 1.7.
- Setiap tahap di peta konsep bagian 1.7 punya baris mulai dan baris selesai, dan baris selesai menyebut kriterianya.

### Bagian B: paket IR untuk `INC-2026-017`

Pakai insiden ransomware `INC-2026-017` di Day 01 (Jumat 2026-10-09, `JKT-FS01`, sumber `JKT-WS-0457` dengan akun `budi.santoso`). Day 01 hanya sampai timeline awal malam itu. Tulis artefak lanjutannya dengan format Day 02-06; semua detail yang tidak ada di Day 01 kamu karang sendiri dan tandai sebagai fiktif.

| No | Artefak | Format dari | Pertanyaan yang harus terjawab |
|---|---|---|---|
| 1 | Kartu jam pertama | Day 03 bagian 2.1 | Apa yang sengaja belum dilakukan, padahal enkripsi sedang berjalan? |
| 2 | Scope statement v1 dan v2 | Day 03 bagian 2.4 | Apa pemicu tertulis yang mempertahankan SEV-1 atau menurunkannya? |
| 3 | Rencana pengambilan bukti | Day 04 bagian 2.1 | Bukti apa yang hilang karena containment didahulukan, dan apa yang masih bisa diambil? |
| 4 | Memo containment dan rencana jam H | Day 05 bagian 2.1 dan 2.2 | Apakah ada yang perlu serentak, atau isolasi segera sudah tepat? |
| 5 | Rencana eradication dan gerbang validasi | Day 06 bagian 2.2 dan 2.4 | Dari mana share `Keuangan` dipulihkan, dan bagaimana tahu backup-nya bersih? |
| 6 | Pernyataan akhir recovery | Day 06 bagian 2.5 | Kriteria mana yang paling sulit dipenuhi untuk ransomware? |

Perbedaan utama dengan `INC-2026-019` ada di urutan: di ransomware, kerusakan sedang berjalan cepat, sehingga containment mendahului bukti dan scoping (Day 03 bagian Ide inti, Day 04 bagian Ide inti). Paketmu harus menunjukkan perbedaan itu secara eksplisit.

### Bagian C: tabletop mini

Jalankan lima inject berikut terhadap `INC-2026-019`, sendiri atau bersama rekan. Setiap inject adalah "bagaimana bila", bukan kejadian yang benar-benar terjadi. Untuk setiap inject, tulis keputusanmu, siapa A-nya, artefak yang berubah, dan bagian Day yang menjadi dasarnya.

1. **Selasa 12:40.** Fajar Nugraha di Bandung tidak bisa dihubungi, dan tidak ada orang lain di POP Bandung yang pernah memegang USB bukti.
2. **Selasa 13:20.** AVML gagal di `jkt-billing01` karena kernel lockdown aktif, dan modul LiME untuk kernel itu tidak ada di toolkit.
3. **Selasa 15:30, go/no-go.** Tim Aplikasi Billing belum menyiapkan kredensial baru `billing_app`.
4. **Rabu 09:00.** Log sinkhole menunjukkan host baru di jaringan Bandung mulai menghubungi `10.20.99.99`.
5. **Kamis 16:00, gerbang validasi.** Login SSH dengan password `svc_billing` dari jaringan workstation ke `jkt-billing02` ternyata berhasil.

Petunjuk: inject 3 menguji go/no-go dan rollback (Day 05 bagian 2.2), inject 4 menguji kriteria selesai containment (Day 05 bagian 1.7), dan inject 5 menguji gerbang validasi dan cutover (Day 06 bagian 1.6 dan 2.4).

### Bagian D: uji lisan lima menit

Rekam dirimu menjawab pesan Dimas di bagian Ide inti dalam lima menit, dengan peta konsep bagian 1.7 sebagai satu-satunya bantuan. Lalu jawab tiga pertanyaan tanpa catatan:

- "Apa beda menunda untuk bersiap dan menunda untuk mengamati?" (Day 05 bagian 1.3)
- "Kenapa rotasi `billing_app` dilakukan tiga kali?" (Day 06 bagian 1.4)
- "Kenapa insiden yang recovery-nya sudah selesai belum boleh ditutup?" (Day 06 bagian 1.7)

Catat bagian yang membuatmu ragu; itu daftar yang perlu diulang sebelum masuk Day 08.

**Hasil yang sebaiknya tersimpan:**

- `latihan/day07-timeline.md` berisi timeline terpadu `INC-2026-019` dan hasil tiga pengecekan bagian A.
- `latihan/day07-paket-inc017.md` berisi enam artefak bagian B, dengan perbedaan urutan dari `INC-2026-019` ditulis eksplisit.
- `latihan/day07-tabletop.md` berisi keputusan, A, artefak yang berubah, dan dasar untuk lima inject.
- Daftar topik yang masih lemah dari uji lisan, beserta Day yang perlu diulang.

### Troubleshooting paket

Tabel ini memuat masalah yang biasa muncul saat paket di atas disusun. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa atau memperbaiki |
|---|---|---|
| Satu keputusan punya dua pemilik di timeline | Keputusan dicatat dari ingatan, bukan dari RACI | Cocokkan setiap KEPUTUSAN dengan RACI Day 02 bagian 2.2 |
| Tahap punya waktu selesai tetapi tanpa kriteria | Selesai ditulis saat tindakan dijalankan | Pakai kriteria Day 05 bagian 1.7 dan Day 06 bagian 1.7 |
| Severity berubah tanpa alasan di timeline | Scribe hanya mencatat label baru | Tambahkan alasan yang merujuk kriteria SEV Day 01 bagian 1.7 |
| Paket ransomware memakai urutan yang sama dengan `INC-2026-019` | Urutan dihafal, bukan diturunkan dari kondisi kerusakan | Tanyakan dulu apakah kerusakan sedang berjalan cepat (Day 04 bagian 1.1) |
| Tabletop berakhir dengan "lanjutkan sesuai rencana" di semua inject | Inject tidak dibaca terhadap kriteria dan pemicu | Untuk setiap inject, sebutkan kriteria atau pemicu tertulis yang tersentuh |
| Uji lisan berubah menjadi daftar tool | Fokus pada perintah, bukan keputusan | Ceritakan per tahap: siapa memutuskan, artefak, kriteria keluar |

## 5. Kesalahan umum dan jebakan

Kesalahan berikut muncul di lebih dari satu Day minggu ini; tiap butir menyebut Day asalnya.

- Menganggap tahap IR berjalan lurus. Rev. 2 sudah menggambar panah balik, dan di `INC-2026-019` insiden mundur ke scoping atau keputusan sebelumnya setidaknya empat kali (Day 01, Day 05, Day 06) [S2].
- Menyebut tahap selesai saat tindakannya dijalankan, bukan saat kriterianya terpenuhi (Day 05, Day 06) [S3][S1].
- Menyamakan severity insiden dengan prioritas alert, atau menganggap severity yang turun berarti dampaknya kecil (Day 01, Day 06).
- IC ikut mengetik perintah, atau IC memutuskan hal yang menjadi wewenang executive sponsor (Day 01, Day 02) [S7].
- Containment satu per satu sejak IOC pertama ditemukan, atau reset kredensial sebelum scope diketahui (Day 03, Day 05) [S4].
- Mendahulukan containment saat tidak ada kerusakan yang berjalan cepat, sehingga bukti volatil hilang (Day 04) [S4][S9].
- Menghapus artefak yang ditemukan dan menganggap host bersih (Day 06) [S3].
- Lupa bahwa rahasia yang dipasang di host terkompromi setelah kompromi juga terpapar (Day 06).
- Menyimpan penundaan tanpa batas waktu dan pemicu tertulis, sehingga keputusan yang disengaja terlihat seperti kelalaian (Day 03, Day 04, Day 05).
- Menutup insiden tanpa post-incident review, atau tanpa memutuskan nasib perubahan sementara dari containment (Day 06).

## 6. Catatan terkini

Bagian ini mengumpulkan status dokumen acuan yang dipakai Day 01-06. Tidak mengubah isi review, tetapi berguna saat ditanya "versi mana yang kamu pakai".

- **NIST SP 800-61 Rev. 3** terbit final April 2025 dan menggantikan Rev. 2 yang berstatus withdrawn sejak 3 April 2025 [S1][S5]. Banyak IR plan, materi, dan lowongan masih memakai empat fase Rev. 2, jadi keduanya perlu dikuasai.
- **SANS Incident Handler's Handbook** (Patrick Kral) terbit 21 Februari 2012; enam tahap PICERL tetap menjadi kosakata umum [S6].
- **Playbook IR dan vulnerability CISA** yang dipakai Day 03-06 adalah edisi November 2021 [S3]. Countermeasure CISA yang dirujuk Day 06 menyebut edisi bertanggal Agustus 2024 [S13]; perbedaan isinya belum dicek untuk catatan ini.
- **NCSC UK** menerbitkan panduan recovery untuk serangan yang sangat mengganggu pada 28 Juli 2026, termasuk konsep minimum viable operations [S10].
- **Mandiant M-Trends 2026** terbit 24 Maret 2026 dengan data investigasi 2025; angka dwell time bergeser setiap tahun, jadi kutip edisi dan tahun datanya [S14].
- **RFC 3227** (Februari 2002) dan **NIST SP 800-86** (Agustus 2006) sudah lama, tetapi urutan volatilitas dan prinsip pengambilan buktinya masih menjadi rujukan baku; contoh alat dan hash di dalamnya sudah usang [S8][S9].
- **Dokumentasi Microsoft** untuk isolasi perangkat, pencabutan akses Entra ID, Kerberos, dan reset krbtgt diperiksa dengan tanggal halaman masing-masing di Day 04-06; batas, nama menu, dan perilaku produk bisa berubah, jadi cek halaman terbaru sebelum mengandalkannya [S11][S12][S15].

## 7. Cheat sheet

```
RANTAI: declare -> scoping -> bukti -> containment -> eradication -> recovery -> post-incident
  tiap tahap: pemilik keputusan (A) | artefak | kriteria keluar TERTULIS
  temuan baru di tahap mana pun -> kembali ke scoping (bukan gagal)
  urutan bisa berubah: kerusakan cepat (ransomware aktif) -> containment dulu

KRITERIA KELUAR
  declare      kriteria insiden terpenuhi; SEV + IC + kanal
  scoping      host C2 | akun + kredensial | jenis persistence | batas visibilitas
  bukti        volatil aman sebelum containment; yang ditunda dicatat
  containment  tindakan terverifikasi + 24 jam tanpa tanda baru + scope disetujui IC
  recovery     aset valid | aset lama ter-image | rahasia dirotasi | akar masalah tertutup
               | 7 hari tenang | perubahan sementara diputuskan
  tutup        setelah post-incident review dan tindak lanjut tercatat

KEPUTUSAN (RACI PT JAB)
  IC: declare, severity, containment (isolasi, blok, akun), retainer dalam kuota, tutup
  exec sponsor: layanan pelanggan, pihak ketiga, biaya di luar kuota, publik
  delegasi bersyarat = keputusan bisnis yang diambil di muka

SEVERITY INC-2026-019: SEV-3 10:40 -> SEV-2 11:50 (svc_billing, jkt-billing01)
  -> SEV-1 13:35 (koneksi ke DB) -> SEV-2 Rabu 17:20 (containment terbukti)
  naik mengikuti blast radius; turun != dampak data kecil

MENUNDA = batas waktu + pemicu tertulis | MENGAMATI = sandbox + Legal + exec sponsor
MUNDUR: host baru (sinkhole) | implant kedua (memori) | kredensial di share | gold image

ARTEFAK: catatan declare | kartu jam pertama | scope statement vN | evidence log + CoC
  | memo keputusan | rencana jam H | update status | rencana eradication | gerbang validasi
  | pernyataan akhir recovery
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "`INC-2026-019` sudah dinyatakan SEV-1 pukul 13:35, jadi severity-nya harus tetap SEV-1 sampai insiden ditutup." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Severity boleh naik dan turun sepanjang insiden, asalkan setiap perubahan dicatat beserta alasannya. Di `INC-2026-019`, Dimas menurunkannya ke SEV-2 Rabu 17:20 karena akses penyerang yang diketahui sudah tertutup dan terverifikasi 24 jam, tidak ada kerusakan yang berjalan, dan dampak data ditangani jalur pelaporan DPO. Penurunan itu tidak berarti dampaknya kecil: severity mengatur siapa terlibat dan ritme update, sedangkan kewajiban atas data berjalan sendiri. Lihat bagian 1.1 dan 1.9.

</details>

**2. Skenario keputusan.** Selasa 10:45, seorang manajer meminta laptop Andi langsung diisolasi "supaya aman". Respons mana yang paling tepat?

- A. Isolasi sekarang, karena laptop itu terbukti beacon ke C2.
- B. Tunda isolasi sambil scoping dan pengamanan bukti, tulis alasannya di bagian "sengaja belum dilakukan", tetapkan batas waktu, dan tulis pemicu yang memajukan containment.
- C. Tunda isolasi sampai analisis forensik lengkap dari retainer selesai, supaya keputusan berdasarkan semua data.

<details><summary>Jawaban</summary>

B. Pagi itu tidak ada kerusakan yang berjalan cepat, scope belum diketahui, dan bukti belum diambil. Mengisolasi satu laptop akan memberi tahu penyerang dan meninggalkan `jkt-billing01` yang baru ditemukan pukul 11:05. Penundaan ini adalah menunda untuk bersiap: berjam-jam, dengan batas dan pemicu. A keliru karena containment berdasarkan scope satu host meninggalkan host lain dan menghilangkan visibilitas. C keliru karena scope tidak harus sempurna; cukup memenuhi syarat minimal, dan menunggu analisis lengkap memberi penyerang waktu. Lihat bagian 1.3, 1.5, dan 1.10.

</details>

**3. Pertanyaan jebakan.** "Bukti sebaiknya diambil setelah containment, supaya penyerang tidak sempat merusak apa-apa selama kita mengambil bukti." Benarkah?

<details><summary>Jawaban</summary>

Tidak sebagai aturan umum. Containment mengubah keadaan sistem: koneksi terputus, memori hilang bila host dimatikan, dan sampel bisa terhapus. AA20-245A menyebut memitigasi sebelum data diambil sebagai kesalahan umum. Pengecualiannya adalah kerusakan yang sedang berjalan cepat, misalnya enkripsi ransomware aktif; di situ menahan kerusakan didahulukan dan bukti diambil dari yang tersisa. Untuk mengurangi risiko selama pengambilan, PT JAB menulis pemicu containment segera dan membuat jarak ke jam H sependek mungkin. Lihat bagian 1.4 dan 1.10.

</details>

**4. Skenario keputusan.** Selasa 17:12, log sinkhole menunjukkan `JKT-WS-0412` menghubungi `10.20.99.99`. Semua tindakan jam H sudah dijalankan pukul 16:12. Apa langkah yang tepat?

- A. Containment tetap dinyatakan berhasil karena semua tindakan di rencana sudah berjalan; host baru ditangani sebagai insiden terpisah.
- B. Kembali ke scoping dan containment: tahan host baru dan akunnya, ambil buktinya, perbarui scope statement, dan hitung ulang periode 24 jam dari saat host ditahan.
- C. Langsung masuk eradication untuk semua host supaya penyerang tidak sempat bereaksi.

<details><summary>Jawaban</summary>

B. Kriteria selesai containment menuntut tidak ada tanda baru selama periode yang ditetapkan, bukan hanya tindakan yang dijalankan. Host yang muncul di sinkhole adalah bagian dari insiden yang sama (email yang sama, C2 yang sama), sehingga scope diperbarui menjadi v3, host ditahan 17:20, bukti diambil 17:45, dan hitungan 24 jam dimulai ulang dari 17:20. A keliru karena memisahkan host baru menyembunyikan bahwa scope ternyata belum lengkap. C keliru karena eradication sebelum containment terbukti berisiko meninggalkan akses yang belum ditemukan. Lihat bagian 1.5, 1.8, dan 1.10.

</details>

**5. Jelaskan ulang.** Jelaskan kepada analyst L1 baru, dalam tiga kalimat, kenapa di `INC-2026-019` setiap tahap punya kriteria keluar tertulis, padahal tim bisa saja langsung pindah ke tahap berikutnya begitu tindakannya selesai.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Tindakan yang sudah dijalankan belum tentu berhasil: jam H selesai pukul 16:12, tetapi satu jam kemudian sinkhole menemukan laptop ketiga yang belum ditahan. Kriteria tertulis membuat kita menunggu bukti, misalnya 24 jam tanpa tanda baru atau tujuh hari tenang setelah server baru dipakai, sebelum menganggap satu tahap selesai dan memulai tahap yang bergantung padanya. Kriteria itu juga membuat pimpinan dan auditor bisa memeriksa keputusan kita, karena 'selesai' berarti syarat tertentu terpenuhi, bukan perasaan bahwa semuanya sudah normal."

Kesalahan yang sering muncul:
- Menjelaskan kriteria sebagai formalitas audit saja, tanpa contoh temuan yang tertangkap karenanya.
- Tidak menyebut bahwa tahap bisa mundur saat kriteria tidak terpenuhi.
- Memakai istilah seperti "RC.RP-06" yang belum dikenal L1.

</details>

**6. Pertanyaan jebakan.** "Dimas adalah IC `INC-2026-019`, jadi dialah yang memutuskan semua langkah besar, termasuk containment parsial `jkt-billing01` dan cutover ke `jkt-billing02`." Benarkah?

<details><summary>Jawaban</summary>

Tidak. IC memegang declare, severity, containment yang termasuk wewenang di muka (isolasi, blok IOC, disable akun), aktivasi retainer dalam kuota, dan pernyataan recovery selesai. Membatasi atau mematikan layanan pelanggan, merotasi kunci pihak ketiga, dan cutover layanan billing adalah keputusan executive sponsor Hendra, dengan IC sebagai pihak yang dikonsultasikan. Yang dipegang IC untuk `jkt-billing01` hanyalah delegasi bersyarat yang ditulis Hendra pukul 15:10. Lihat bagian 1.2 dan 1.9.

</details>

**7. Interview question (English).** "Walk me through an incident you handled from detection to recovery. What decisions did you make, and how did you know each phase was done?"

<details><summary>Sample answer</summary>

"A recent case started with an EDR alert for encoded PowerShell on a billing clerk's laptop. We declared it at low severity, and I deliberately didn't isolate the laptop yet, because nothing destructive was happening and we didn't know the scope. Pivoting on the C2 domain and the user's activity, we found the attacker had read a service account password from a script and used it to SSH into our billing server, so severity went up and we informed legal and the data protection officer. When we saw the implant connected to the customer database, we raised it to our highest level and activated our DFIR retainer. Before containing anything we captured memory and volatile data from all three hosts, with an evidence log and chain of custody. The business owner chose partial containment of the billing server so payments could continue, with a written trigger allowing us to shut it down if things got worse, and we executed all actions in one coordinated window. That window wasn't the finish line: our sinkhole caught a third laptop an hour later, so we went back to scoping and restarted the 24-hour clock. Memory analysis found a second copy of the implant, so we rebuilt the server from a gold image instead of cleaning it, closed the root cause, rotated every secret the attacker could have seen including ones we installed during containment, and cut over after a validation gate. We declared recovery complete only after seven quiet days against written criteria, and then moved to the post-incident review."

What makes this answer strong: it tells one incident as a chain of decisions with owners, explains a deliberate delay and its limits, shows a loop back to scoping instead of hiding it, and ends every phase with a criterion rather than an action.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | NIST SP 800-61 Rev. 3: Incident Response Recommendations and Considerations for Cybersecurity Risk Management: A CSF 2.0 Community Profile (PDF) | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf | primer | April 2025; diakses 2026-10-14 dan 2026-10-15 | Tinggi. Definisi insiden, model tiga lapis, DE.AE-08, RS.MA, RS.AN-07, RS.AN-08, ID.IM, RS.MI, RC.RP-05, RC.RP-06; dirangkum dari Day 01-06 |
| S2 | NIST SP 800-61 Rev. 2: Computer Security Incident Handling Guide (PDF) | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf | primer | Agustus 2012 (lebih dari 3 tahun, withdrawn); diakses 2026-10-14 dan 2026-10-15 | Tinggi untuk siklus empat fase dan panah balik, dimensi dampak, analisis awal, kriteria containment |
| S3 | CISA: Cybersecurity Incident and Vulnerability Response Playbooks (PDF) | https://www.cisa.gov/sites/default/files/publications/Federal_Government_Cybersecurity_Incident_and_Vulnerability_Response_Playbooks_508C.pdf | primer | November 2021; diakses 2026-10-15 | Tinggi. Scoping, hipotesis, containment berhasil, syarat eradication, eradication dan recovery bersamaan |
| S4 | CISA: Technical Approaches to Uncovering and Remediating Malicious Activity (AA20-245A) | https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-245a | primer | 2020-09-01, revisi 2020-09-24 (lebih dari 3 tahun); diakses 2026-10-15 | Tinggi. Kesalahan umum (menyentuh infrastruktur penyerang, mitigasi sebelum bukti, blok dan reset dini), krbtgt dua kali |
| S5 | NIST CSRC: SP 800-61 Rev. 2 (halaman publikasi) | https://csrc.nist.gov/pubs/sp/800/61/r2/final | primer | withdrawn 2025-04-03; diakses 2026-10-14 | Tinggi untuk status withdrawn |
| S6 | SANS: Incident Handler's Handbook (Patrick Kral) | https://www.sans.org/white-papers/33901 | sekunder | 2012-02-21 (lebih dari 3 tahun); diakses 2026-10-14 | Sedang-tinggi. Enam tahap PICERL |
| S7 | PagerDuty Incident Response Documentation: Incident Commander training | https://response.pagerduty.com/training/incident_commander/ | sekunder (vendor) | diakses 2026-10-14 | Sedang-tinggi. IC tidak mengerjakan remediasi, serah terima komando |
| S8 | RFC 3227: Guidelines for Evidence Collection and Archiving (BCP 55) | https://www.rfc-editor.org/rfc/rfc3227.txt | primer | Februari 2002 (lebih dari 3 tahun); diakses 2026-10-15 | Tinggi. Urutan volatilitas, hal yang dihindari, chain of custody |
| S9 | NIST SP 800-86: Guide to Integrating Forensic Techniques into Incident Response (PDF) | https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-86.pdf | primer | Agustus 2006 (lebih dari 3 tahun); diakses 2026-10-15 | Tinggi. Urutan pengambilan data volatil, keputusan mengambil data volatil |
| S10 | NCSC UK: Recovering from a highly disruptive cyber attack, Section 2 (Recovery and ongoing investigations) | https://www.ncsc.gov.uk/collection/disruptive-cyber-attacks/recovering/2-recovery-ongoing-investigations | primer | Terbit 2026-07-28, direview 2026-10-01; diakses 2026-10-15 | Tinggi. Minimum viable operations, risiko memulihkan sebelum penyerang keluar |
| S11 | Microsoft Learn: Revoke user access in an emergency in Microsoft Entra ID | https://learn.microsoft.com/en-us/entra/identity/users/users-revoke-access | primer (dokumentasi vendor) | ms.date 2026-06-19; diakses 2026-10-15 | Tinggi. Disable dan reset dua kali, revoke sessions, umur access token |
| S12 | Microsoft Learn: AD Forest Recovery, Reset the krbtgt password | https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password | primer (dokumentasi vendor) | ms.date 2025-05-21; diakses 2026-10-15 | Tinggi. Reset dua kali dengan jeda |
| S13 | CISA Eviction Strategies Tool: CM0050 Reset Kerberos Ticket Granting Ticket (KRBTGT) Password Twice | https://www.cisa.gov/eviction-strategies-tool/info-countermeasures/CM0050 | primer | Maret 2025; diakses 2026-10-15 | Tinggi. Tujuan reset krbtgt, cek replikasi, dampak |
| S14 | Google Cloud Blog: M-Trends 2026 | https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026/ | sekunder (laporan vendor IR) | 2026-03-24; diakses 2026-10-15 | Sedang-tinggi. Median dwell time global 14 hari |
| S15 | Microsoft Learn: Take response actions on a device in Microsoft Defender for Endpoint | https://learn.microsoft.com/en-us/defender-endpoint/respond-machine-alerts | primer (dokumentasi vendor) | ms.date 2026-07-23; diakses 2026-10-15 | Tinggi. Isolasi perangkat dan paket investigasi |
| S16 | BPK JDIH: UU Nomor 27 Tahun 2022 tentang Pelindungan Data Pribadi | https://peraturan.bpk.go.id/Details/229798/uu-no-27-tahun-2022 | primer (metadata regulasi) | ditetapkan dan diundangkan 2022-10-17; diakses 2026-10-14 | Tinggi untuk identitas UU |
| S17 | Pasal.id: UU 27/2022 Pasal 46 | https://pasal.id/peraturan/uu/uu-no-27-tahun-2022/pasal-46 | sekunder (agregator regulasi) | diakses 2026-10-14 | Sedang. Teks Pasal 46; penjelasan pasal tidak tampil |
| S18 | NCSC UK: Incident management collection, halaman Processes for Cyber Incident Response | https://www.ncsc.gov.uk/collection/incident-management/cyber-incident-response-processes | primer | diakses 2026-10-14 | Tinggi. Wewenang di muka untuk tim teknis, kontak 2 orang dan 2 metode, kanal alternatif |
| S19 | Microsoft Learn: [MS-KILE] Check Account Policy for Every Session Ticket Request | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/e19be8b8-9130-40a4-9cd1-92d0cbd46a51 | primer (spesifikasi protokol) | diperbarui 2026-04-27; diakses 2026-10-15 | Tinggi. Tiket Kerberos yang sudah terbit tidak langsung dicabut saat akun dinonaktifkan |

**Catatan sumber:** Day ini tidak memakai sumber baru; setiap klaim berasal dari Day 01-06 dan sumber yang sama dirujuk ulang. Peta konsep di bagian 1.7, tiga benang di bagian 1.8 sampai 1.10, dan glosarium adalah susunan catatan ini, bukan model resmi salah satu sumber; definisi di glosarium adalah parafrase untuk belajar. Titik mulai hitungan 3 x 24 jam UU PDP Pasal 46 masih perlu dicek di PDF resmi dan penjelasan pasal. Semua isi PT JAB, termasuk timeline `INC-2026-019`, inject tabletop di bagian 2-4, dan nama orang, adalah contoh fiktif.
