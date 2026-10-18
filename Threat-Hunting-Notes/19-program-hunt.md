---
day: 19
title: 'Program hunt: model tim, kalender, dan jalur ke detection engineering'
researched_on: 2026-10-18
versions_checked: 'SANS blog "From Alerts to Adversaries" (Jan D''Herdt, 2026-08-20); PEAK framework (Splunk, 2023-04-18) dan artikel metrik PEAK (2023-08-02); TaHiTI methodology whitepaper (berkas di-host 2026-03); Hunting Maturity Model (Sqrrl "Hunt Evil"); SANS 2026 Threat Hunting Survey (rilis pers 2026-09-23); SCYTHE Purple Team Exercise Framework v4; Atomic Red Team (repo, 1.878 atomics per akses 2026-10-18); Invoke-AtomicRedTeam 2.3.0 (PowerShell Gallery, 2025-03-20); MITRE CTID Adversary Emulation Library; Intel 471 (2026-02-10); MITRE ATT&CK v20; Splunk Enterprise 10.6 (SPL); rujukan Threat-Hunting Day 01-18'
---

# Day 19: Program hunt (model tim, backlog, kalender, purple team, dan jalur ke detection engineering)

Cakupan: mengubah rangkaian hunt yang sudah berjalan menjadi program yang bertahan: memilih model tim beserta konsekuensinya bagi antrean SOC, memeriksa prasyarat, naik tingkat kematangan tanpa melompat, menjalankan backlog dan kalender, memasukkan latihan purple team dengan Atomic Red Team, membakukan jalur ke detection engineering, memantau kesehatan program, dan menetapkan kriteria evaluasi sebelum angkanya keluar.

## Ide inti

Program hunt jarang mati karena hunt-nya buruk. Ia mati diam-diam karena hunting adalah pekerjaan pertama yang dikorbankan saat antrean naik: tidak punya tenggat, tidak ada pelanggan yang menelepon, dan selalu bisa "dikerjakan minggu depan". Program yang bertahan punya empat hal yang tidak dimiliki hunt sesekali. Pertama, waktu yang dilindungi dengan aturan tertulis, sehingga setiap hari yang diambil tercatat dan bisa dipertanyakan. Kedua, backlog yang sudah dinilai sehingga pertanyaan "hunt apa minggu ini" tidak dijawab dari nol. Ketiga, jalur keluar ke detection engineering yang punya pemilik, format, dan tenggat, sehingga hasil hunt tidak mengendap. Keempat, kriteria evaluasi yang ditulis sebelum angkanya keluar, sehingga keputusan "lanjut, ubah, atau hentikan" tidak ditentukan oleh angka yang kebetulan terlihat bagus. Bentuk tim (satu analyst paruh waktu, rotasi, atau peran khusus) adalah keputusan tentang siapa yang menanggung biaya waktu itu, dan setiap pilihan punya harga yang dibayar antrean L1 dan jadwal L2.

Kamu sudah mengenal pola ini dari NOC. Program preventive maintenance yang benar-benar jalan bukan yang punya engineer paling rajin, melainkan yang jendela kerjanya dikunci di kalender change jauh hari, antrean tiket PM-nya diprioritaskan ulang setiap minggu, temuannya masuk ke change management atau menjadi alarm NMS lewat tim yang jelas, dan uji failover terjadwal membuktikan bahwa alarm memang berbunyi saat link utama diputus. Engineer yang ditarik ke gangguan setiap kali jadwal PM tiba tidak pernah menyelesaikan PM-nya, dan manajer baru sadar saat kabel yang seharusnya diperiksa bulan lalu putus. Batas analoginya: maintenance jaringan punya ukuran alami (uptime, MTTR) dan checklist vendor, sedangkan hunting tidak, sehingga kriteria keberhasilan harus ditulis sendiri sebelum evaluasi. Uji failover juga menguji perangkat yang patuh pada skrip, sedangkan test Atomic hanya meniru satu prosedur; penyerang sungguhan memilih prosedur yang belum diuji.

```
 masukan: intel | insiden lama | celah monitoring | hunt sebelumnya | usulan L1 | keahlian domain
                   |
                   v
 BACKLOG (entri ABLE + kesiapan data) --- dinilai ulang tiap Selasa pagi, skor, tutup yang basi
                   |
                   v
 KALENDER dikunci 1 kuartal: Selasa/Kamis = hunt | purple bulanan | cadangan | tinjauan kuartal
     aturan: hari hunting hanya diambil atas keputusan Dimas, dicatat, diganti bila bisa
                   |
        +----------+-----------+
        v                      v
      HUNT                PURPLE TEAM (Atomic Red Team)
  (temuan, celah,       detection hasil hunt + uji positif
   usulan deteksi)        hunt negatif lama -> skor 0-5
        |                      |
        +----------+-----------+
                   v
 JALUR KELUAR: IR (Dimas) | detection engineering (Sari: antrean, tenggat 10 hari kerja,
               keputusan tercatat) | pemilik celah (register G/M)
                   |
                   v
 KESEHATAN PROGRAM: hari terlindungi | umur usulan | umur backlog | negatif teruji |
                    beban L1 | ketergantungan satu orang
                   |
                   v
 EVALUASI JULI (kriteria ditulis April): lanjut | ubah model | hentikan  --> kembali ke backlog
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan, kantor pusat dan data center di Jakarta, serta POP regional di Bandung, Surabaya, dan Medan. SOC PT JAB satu lantai dengan NOC: enam analyst L1 dalam tiga shift, empat analyst L2 (Sari Kusuma, Yoga Pratama, Rudi Hartanto, dan kamu), dan SOC lead Dimas Prasetyo. Sari juga memegang konten detection di Splunk Enterprise Security (ES). Program hunt PT JAB adalah percobaan dua kuartal (Februari sampai Juli 2027) yang disetujui Direktur Teknologi Hendra Wijaya; kamu memegangnya setiap Selasa dan Kamis. Evaluasi akhir Q1 berlangsung Rabu 2027-03-31 (Day 16). Selasa 2027-04-06 kamu menjalankan tiga hunt identitas dan cloud (`HUNT-2027-029` sampai `-031`, Day 17), dan Kamis 2027-04-08 satu hunt di notebook (`HUNT-2027-032`, Day 18). Selasa 2027-04-13 hari hunting-mu habis untuk menggantikan piket eskalasi L2 karena Yoga sakit; tidak ada insiden, hanya antrean. Kamis 2027-04-15 pukul 08:20, Dimas menulis:

> "Pagi. Pak Hendra minta usulan bentuk program hunt untuk sisa percobaan sampai akhir Juli, dan sesudahnya kalau dilanjutkan. Beliau menyebut tiga pilihan: tetap kamu sendiri dua hari seminggu, digilir di antara L2, atau ada peran khusus. Apa pun pilihannya, aku perlu tahu dampaknya ke antrean L1 dan ke piket serta on-call L2; Selasa kemarin saja hari hunting-mu habis buat menggantikan Yoga. Beliau juga tanya kita sekarang di tingkat kematangan mana dan apa yang realistis sampai Juli. Apa prasyarat yang harus beres dulu? Backlog dan kalendernya mau dijalankan bagaimana, supaya tidak tiap minggu mikir dari nol? Sari usul latihan purple team pakai Atomic Red Team; itu masuk di mana? Jalur usulan ke Sari tolong dibakukan, jangan sampai ada yang menunggu enam minggu lagi seperti certutil. Terakhir, metrik apa yang kita pantau supaya program ini sehat, dan kapan di evaluasi Juli kita bilang berhasil, perlu diubah, atau dihentikan. Kalau bisa, rencana 90 hari dan kalendernya, satu halaman untuk Pak Hendra."

Pesan itu memuat tujuh pertanyaan:

1. Model tim mana yang dipakai, dan apa konsekuensinya bagi antrean L1 serta piket dan on-call L2?
2. Prasyarat apa yang harus ada, dan mana yang belum?
3. Di tingkat kematangan mana program sekarang, dan apa target realistis sampai Juli tanpa melompat?
4. Bagaimana backlog dan kalender dijalankan?
5. Di mana purple team dengan Atomic Red Team masuk?
6. Bagaimana jalur hunt ke detection engineering dibakukan?
7. Metrik kesehatan apa yang dipantau, dan kapan program dinyatakan berhasil, perlu diubah, atau dihentikan pada evaluasi Juli?

Pertanyaan 1 dijawab di bagian 1.1 dan 1.2, pertanyaan 2 di bagian 1.3, pertanyaan 3 di bagian 1.4, pertanyaan 4 di bagian 1.5, 1.6, dan 2.2 sampai 2.4, pertanyaan 5 di bagian 1.7 dan 2.5, pertanyaan 6 di bagian 1.8 dan 2.6, dan pertanyaan 7 di bagian 1.9, 1.10, 2.7, dan 2.8. Bagian 2.1 menyusun angka program per 15 April sebagai titik awal, dan bagian 2.9 berisi satu halaman untuk Hendra serta jawaban untuk Dimas.

**Kapan relevan:** saat hunt sudah berjalan beberapa minggu dan pertanyaannya bergeser dari "bagaimana menjalankan hunt" ke "bagaimana program ini bertahan"; saat manajemen bertanya soal bentuk tim atau rekrutmen; saat hari hunting mulai sering diambil pekerjaan lain; dan saat menjelang evaluasi yang menentukan nasib program.
**Kapan bukan jawaban:** saat program belum pernah menjalankan satu hunt pun (mulai dari satu hunt dan laporannya, Day 01 sampai 02, bukan dari kalender kuartal); saat ada insiden aktif (hunting berhenti dan IR yang memegang, Day 02 bagian 1.6); dan saat data dasarnya belum ada (perbaiki telemetri dulu, Day 04), karena kalender yang rapi di atas data yang buta hanya menjadwalkan hasil "data tidak cukup".

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (HMM, PEAK, TaHiTI, backlog, abstract, ABLE, kartu kesiapan, positive control, Kategori hasil, blok Metrik, register celah, `origin_hunt`, rasio hunt ke detection, laporan hunter) tidak diulang. Tabel ini hanya memuat istilah baru yang dipakai di Day ini.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Program hunt | Hunting yang dijalankan dengan ritme, backlog, jalur keluar, metrik, dan evaluasi yang tetap, bukan sesekali | Program preventive maintenance tahunan dengan jendela kerja terkunci |
| Model tim | Cara organisasi menyediakan orang untuk hunting: eksternal, dedikasi, hibrida, atau periodik | Siapa yang mengerjakan PM: vendor, tim PM khusus, atau engineer operasional bergiliran |
| Blok waktu terlindungi | Hari hunting yang hanya boleh diambil dengan keputusan tertulis, dicatat, dan diganti bila bisa | Jendela maintenance yang sudah disetujui CAB dan tidak dipakai untuk pekerjaan lain |
| Hunter pendamping | Analyst lain yang ikut hunt terjadwal untuk belajar dan menjadi cadangan | Engineer junior yang ikut PM bersama senior sebelum memegang jadwal sendiri |
| Purple team | Latihan bersama: teknik serangan dijalankan secara terbuka dan terkendali, tim deteksi dan respons mencatat apa yang terlihat dan apa yang memicu | Uji failover terjadwal bersama tim lain sambil mencatat alarm mana yang berbunyi |
| Atomic Red Team | Pustaka test kecil yang dipetakan ke ATT&CK, masing-masing meniru satu prosedur dan punya GUID tetap | Kumpulan skrip uji per jenis gangguan (loop test, port shut) |
| Invoke-AtomicRedTeam | Modul PowerShell untuk menjalankan, memeriksa prasyarat, membersihkan, dan mencatat test Atomic | Skrip otomatis yang menjalankan uji dan menyimpan log hasilnya |
| Skor hasil purple | Skala 0 sampai 5 per teknik di PTEF, dari tanpa visibilitas sampai respons penuh | Tingkat keberhasilan uji failover: tidak terlihat, alarm berbunyi, sampai pemulihan tuntas |
| Anggaran antrean L1 | Batas tambahan alert per minggu dari detection baru yang disepakati sebelum detection diaktifkan | Batas jumlah alarm baru yang boleh ditambahkan ke NMS sebelum NOC kewalahan |
| Tenggat keputusan | Batas waktu Sari memberi keputusan atas usulan deteksi, termasuk tunda atau tolak | SLA review change request |
| Metrik kesehatan program | Ukuran proses yang memberi peringatan dini (hari terlindungi, umur usulan, umur backlog), berbeda dari metrik outcome | Indikator PM tertunda dan umur tiket PM, bukan uptime |
| Kriteria evaluasi | Ambang "lanjut, ubah, hentikan" yang ditulis sebelum periode berakhir | Kriteria acceptance test yang disepakati sebelum uji dimulai |

### 1.1 Model tim dan kelemahannya

Pertanyaan pertama Dimas menyebut tiga pilihan, padahal literatur program hunting biasanya memakai empat model. Panduan SANS tentang memulai dan mematangkan program hunting (Jan D'Herdt, Agustus 2026) menyebut keempatnya beserta kelemahan masing-masing [S1]. Tabel berikut meringkasnya; baca kolom kanan, karena kelemahan itu yang akan muncul di PT JAB bila tidak diantisipasi.

| Model | Bentuk | Kelemahan yang harus diantisipasi |
|---|---|---|
| Eksternal | Jasa pihak ketiga | Cepat memperkenalkan konsep, tetapi tidak punya pengetahuan lingkungan yang dalam, sehingga jarang cocok jangka panjang [S1] |
| Dedikasi | Hunter penuh waktu, biasanya di organisasi besar | Risiko silo antara hunter dan analyst SOC [S1] |
| Hibrida (gabungan) | Analyst SOC atau responder hunting di samping tugas rutin | Keterampilannya sudah ada, tetapi prioritas yang bersaing bisa membuat tidak ada waktu untuk hunting [S1] |
| Periodik | Staf ditugaskan hunting dengan ritme tetap (mingguan, dua mingguan, bulanan) | Butuh rencana yang jelas dan tugas spesifik untuk efektif [S1] |

Program PT JAB saat ini adalah campuran hibrida dan periodik: satu analyst L2 yang tetap ikut on-call, dengan ritme tetap Selasa dan Kamis. Kelemahan hibrida sudah terlihat Selasa 13 April. Penangkal yang bekerja untuk model hibrida bukan niat baik, melainkan blok waktu yang dilindungi seperti jadwal on-call: tercatat di kalender, punya aturan siapa yang boleh mengambilnya, dan setiap pengambilan dicatat sehingga polanya terlihat (bagian 1.6).

Yang membedakan hunting dari pekerjaan antrean juga perlu dinyatakan terbuka: hunting bukan menangani alert. Bila kinerja hunter diukur dengan jumlah tiket yang ditutup atau jumlah hunt per orang, program akan mati sendiri tanpa ada yang mengumumkannya. Intel 471 menggolongkan jumlah hunt per hunter sebagai metrik yang merusak program, karena mendorong burnout dan membuat talenta keluar [S8].

Data survei memberi konteks, bukan jawaban. Survei SANS 2026 mencatat 58% responden menjalankan hunting in-house dan outsourcing turun dari 30% pada 2025 menjadi 18% [S15]. Hambatan utama kini data (50%), di atas staf terampil (45%) [S15]. Untuk PT JAB, angka kedua itu yang paling relevan: menambah orang sebelum data merata berarti membayar orang untuk menemukan celah yang sudah diketahui (Day 01 bagian 1.7).

### 1.2 Tiga pilihan untuk PT JAB dan harganya

Pertanyaan pertama Dimas sebenarnya tentang harga: siapa yang menanggung waktu hunting. Untuk menjawabnya, kamu butuh tiga fakta operasional SOC PT JAB. Eskalasi L1 ke L2 sepanjang Q1 rata-rata 5,8 per hari kerja (dari sistem tiket SOC). Piket eskalasi harian dibagi di antara L2 yang tidak sedang hunting, sehingga pada Selasa dan Kamis hanya Sari, Yoga, dan Rudi yang menerimanya. On-call di luar jam kerja bergilir mingguan di antara empat L2, termasuk kamu, dan hari hunting tidak membebaskan dari on-call. Tabel berikut membandingkan pilihan Hendra dengan konsekuensinya; baca kolom piket dan on-call, karena di situlah biaya yang dirasakan rekanmu.

| Pilihan | Bentuk | Antrean L1 | Piket dan on-call L2 | Kontinuitas dan risiko |
|---|---|---|---|---|
| A. Satu analyst dua hari (sekarang) | Kamu, Selasa dan Kamis | Bertambah dari detection hasil hunt (12 alert dalam 4 minggu, bagian 2.1) | Selasa dan Kamis piket dibagi 3 orang (sekitar 1,9 eskalasi per orang per hari, dibanding 1,5 bila 4 orang); on-call tetap 1 dari 4 minggu | Satu titik kegagalan: bila kamu sakit, cuti, atau ditarik, program berhenti; belum ada orang lain yang pernah memimpin hunt |
| B. Rotasi L2 | Yoga, Rudi, dan kamu bergiliran memegang dua hari per minggu, misalnya per bulan; Sari tidak masuk karena memegang konten detection | Sama dengan A | Sama dengan A pada hari hunting; beban berpindah orang setiap bulan | Pengetahuan menyebar dan triase L2 ikut membaik, tetapi setiap pergantian butuh pemanasan, mutu hunt bervariasi, dan backlog butuh satu koordinator tetap |
| C. Peran khusus penuh waktu | Kamu dipindah ke hunting lima hari, atau merekrut hunter baru | Bertambah lebih cepat bila jumlah usulan naik; jalur ke Sari bisa menjadi leher botol | Bila kamu dipindah: piket setiap hari dibagi 3 orang, on-call menjadi 1 dari 3 minggu (dari sekitar 13 menjadi sekitar 17 minggu per tahun per orang). Bila merekrut: biaya dan masa orientasi | Risiko silo [S1]; kapasitas tambahan menabrak data yang belum siap (229 workstation tanpa Sysmon) |
| D. Eksternal | Jasa hunting pihak ketiga | Tergantung kontrak | Tidak berubah | Tidak punya konteks PT JAB [S1]; data log keluar organisasi, sehingga DPO perlu dilibatkan |

Dari tabel itu, rekomendasi untuk sisa percobaan adalah pilihan A dengan tiga tambahan, disebut A+ di Day ini:

- **Aturan perlindungan tertulis.** Hari hunting hanya boleh diambil untuk insiden SEV-1 atau SEV-2, atau atas keputusan Dimas untuk kebutuhan lain. Setiap pengambilan dicatat di `jab_hunt_days.csv` dan diganti dengan hari cadangan di kalender bila bisa (bagian 1.6). Selasa 13 April akan tetap diambil di bawah aturan ini, tetapi keputusannya milik Dimas dan tercatat, bukan terjadi begitu saja.
- **Hunter pendamping.** Yoga ikut setengah hari (08:00 sampai 12:00) pada Kamis tertentu, enam kali sampai Juli, lalu memimpin satu hunt sendiri dengan kamu sebagai reviewer. Ini menguji pilihan B dengan biaya kecil dan mengurangi ketergantungan pada satu orang. Harganya jelas: pada pagi itu piket hanya Sari dan Rudi, sehingga Dimas perlu menyetujui jadwalnya di awal.
- **Cadangan yang sudah ada dipakai.** Rudi sudah menjadi cadangan untuk notebook `jkt-hunt-nb01` (Day 18) dan investigator di Velociraptor (Day 09); ia diminta menjalankan satu laporan hunter terjadwal setiap bulan, sehingga laporan itu tidak berhenti saat kamu tidak ada.

Untuk setelah Juli, keputusan diambil dari kriteria bagian 1.10, bukan dari preferensi. Pilihan C baru masuk akal bila dua hal terjadi bersamaan: anggaran rollout Sysmon disetujui (hambatan data berkurang), dan backlog berisi lebih banyak entri SIAP daripada yang bisa dikerjakan dua hari per minggu selama dua bulan berturut-turut. Tanpa keduanya, hunter penuh waktu akan menghabiskan sebagian besar waktunya menemukan celah yang sama.

### 1.3 Prasyarat: data, alat, orang

Pertanyaan kedua Dimas punya jawaban yang sederhana: hunt tidak akan lebih baik daripada datanya. Panduan SANS menyebut tiga kelompok prasyarat [S1]: data (telemetri yang lengkap, terikat waktu, bisa diakses, dengan retensi cukup: process tree EDR, Sysmon, DNS dan proxy, NetFlow, autentikasi direktori dan cloud, serta CTI), alat (platform yang bisa dikuerikan tim dengan lancar, misalnya Splunk dan Velociraptor, ditambah Python atau PowerShell), dan orang (peran hunter, analyst SOC, responder, dan analis intel yang jelas). Tabel berikut menerapkannya ke PT JAB per 15 April; baca kolom "Belum", karena itulah yang menjadi bagian rencana, bukan alasan menunda program.

| Kelompok | Sudah ada | Belum | Pemilik |
|---|---|---|---|
| Data endpoint | Sysmon di 214 host (40% workstation); GPO audit 4688/4698 kini juga di Bandung dan POP (63 dari 81 workstation benar-benar mengirim, Day 16); Velociraptor menjawab 428 dari 443 host | Sysmon untuk 229 workstation (butuh keputusan anggaran); field Sysmon (hash, `OriginalFileName`, koneksi) di populasi regional | Agung Prabowo, Hendra (anggaran) |
| Data jaringan | Proxy, DNS, firewall Jakarta dan POP | Retensi `proxy` dan `dns` 30 hari (index DNS kantor 90 hari dijadwalkan, G16); laptop di luar kantor lewat split tunnel tanpa pemilik celah (G15); pemetaan IP ke host POP dari lease DHCP (G22) | Agung, Bambang Hartono |
| Data identitas dan cloud | Sign-in interaktif dan non-interaktif serta audit Entra 1 tahun di `o365`; CloudTrail di `aws` | Sign-in service principal dan managed identity tidak diekspor (G21); `sourceIdentity` tidak diwajibkan (M20) | Agung, Lutfi Hakim |
| Data Linux | Wazuh dan archives untuk 4 server; auditd execve di 2 server | auditd di `jkt-portal02` dan `jkt-radius01` (G08); `jkt-netops01` tanpa agent (G19) | Lutfi, Agung |
| Alat | Role `jab_hunter` dengan workload rule; `jkt-velo02`; Wazuh; `jkt-hunt-nb01`; repo `jab-hunt` dan `jab-detections` dengan pipeline Sigma; VM lab `jab-lab-win11` dan `jab-lab-splunk01`; Atomic Red Team di lab | VM Linux lab dengan agent Wazuh untuk menguji rule Wazuh; host uji di produksi untuk purple team (butuh keputusan, bagian 1.7) | Agung, Dimas |
| Orang | Hunter (kamu); sponsor dan IC (Dimas); pemilik konten detection (Sari); pemilik telemetri (Agung, Bambang, Lutfi); DPO (Agus Setiawan); Risiko dan Kepatuhan (Nina Kartika); cadangan notebook (Rudi); pengusul L1 (Gilang Ramadhan, Dwi Cahyono) | Orang kedua yang pernah memimpin hunt; analis intel khusus (peran CTI dipegang hunter dan Sari) | Dimas |

Dua hal dari tabel ini sering terlewat. Pertama, siapa yang berwenang menyatakan temuan hunt menjadi insiden harus jelas sebelum ada temuan: di PT JAB itu Dimas sebagai IC, dan jalurnya sudah teruji saat `INC-2027-040` (35 menit dari terlihat sampai dinyatakan insiden, Day 15 bagian 1.5). Kedua, celah yang belum ditutup bukan alasan menunda program; perbaikan visibilitas adalah hasil hunt yang sah dan tercatat di register (Day 15 bagian 1.7). Yang tidak boleh adalah menjanjikan hasil di area yang datanya belum ada.

### 1.4 Naik tingkat HMM tanpa melompat

Pertanyaan ketiga Dimas sudah punya alat ukur sejak Day 01: Hunting Maturity Model, HMM0 sampai HMM4 [S4], dengan level ditentukan oleh pertanyaan tertinggi yang bisa dijawab "ya" dengan bukti (Day 01 bagian 1.5). Day ini menambahkan cara naiknya. Panduan SANS memberi nasihat yang sering diabaikan: jangan mencoba melompat dari HMM0 ke HMM3 dalam satu kuartal, perbaiki telemetri dulu, baru berinvestasi pada teknik analisis dan otomasi [S1]. Artikel metrik PEAK menyebut sebagian besar organisasi hunting setidaknya berada di HMM2, banyak yang membidik HMM3, dan idealnya HMM4, yaitu mengubah sebagian besar hunt menjadi detection otomatis [S7]. Tabel berikut adalah urutan naik yang dipakai PT JAB; baca kolom kanan, karena itu bukti yang diminta saat evaluasi.

| Dari | Ke | Pekerjaan yang sebenarnya | Bukti di PT JAB per 15 April |
|---|---|---|---|
| HMM0 | HMM1 | Kumpulkan data dari host, jaringan, dan aplikasi; validasi; mulai mencari indikator | Terlewati sebelum program (Day 01 bagian 1.5) |
| HMM1 | HMM2 | Perbaiki telemetri; jalankan prosedur hunting yang sudah dipublikasikan secara terjadwal, dengan dokumentasi yang bisa diulang orang lain | Kalender Selasa dan Kamis sejak 2 Februari; 29 laporan dengan Kategori hasil dan blok Metrik; register celah G01 sampai G22 |
| HMM2 | HMM3 | Buat prosedur analisis sendiri: baseline, stacking ternormalisasi, notebook, positive control | `HUNT-2027-026` (side-load dengan dua artifact), `-029` (tahap B dengan tipe ASN dan ASN baru), `-032` (join autostart dan beacon lintas sumber); 7 dari 26 hasil negatif dengan uji positif |
| HMM3 | HMM4 | Otomasi prosedur yang terbukti: hunt berulang menjadi detection atau job terjadwal | Awal: 12 detection aktif dari 9 hunt, 6 laporan hunter terjadwal, hunt Velociraptor mingguan; masih ditinjau manusia |

Penilaian per 15 April: perilaku HMM2 terpenuhi dengan bukti, bukti awal HMM3 menguat, HMM4 belum. Target Juli tetap sama dengan yang ditulis di Day 01: perilaku HMM2 yang konsisten dan awal HMM3 yang bisa ditunjukkan. Yang berubah adalah cara mengukurnya: "awal HMM3" ditulis sebagai kriteria yang bisa dihitung (bagian 1.10), bukan klaim.

Tanda melompat terlalu cepat mudah dikenali. Tim membicarakan model machine learning sementara retensi DNS masih 30 hari; rencana kuartal berikutnya berisi "otomasi hunting dengan AI" padahal 19 dari 26 hasil negatif belum pernah dibuktikan dengan uji positif; atau peran khusus diminta sebelum data endpoint merata. PEAK memang punya tipe hunt model-assisted (M-ATH) [S2], dan panduan SANS menaruh satu hunt berbantuan model di fase pelembagaan, bukan di awal [S1]. Untuk PT JAB, jenis itu baru masuk akal setelah hypothesis-driven dan baseline berjalan stabil.

### 1.5 Backlog hipotesis yang dinilai ulang

Pertanyaan keempat Dimas ("supaya tidak tiap minggu mikir dari nol") dijawab oleh backlog yang sehat. TaHiTI menyimpan setiap trigger sebagai investigation abstract di backlog; abstract hanya deskripsi dasar yang dirinci ulang saat hunt dipilih, backlog tidak perlu alat rumit, dan yang penting adalah backlog memberi cukup gambaran untuk memilih abstract paling relevan untuk hunt berikutnya [S3]. Penutup whitepaper TaHiTI menegaskan hal yang sama dari sisi lain: pilih, prioritaskan, dan dokumentasikan masukan (trigger) dengan cermat [S3].

Masukan backlog datang dari pemicu yang disebut TaHiTI: intel aktor, hunt lain, use case monitoring yang belum lengkap, insiden historis, red teaming, analisis crown jewel, keahlian domain, dan ATT&CK [S3]. Setiap jenis butuh jalur masuk yang jelas:

1. **Intel.** Laporan aktor atau kampanye yang relevan menjadi hipotesis perilaku, bukan daftar indikator. Indikator tetap dicari lewat threat intelligence ES (pekerjaan HMM1, Day 03 bagian 1.1).
2. **Insiden historis dan post mortem.** Setiap laporan insiden yang memuat "baru ketahuan setelah" atau "tidak ada alert" menyisakan hipotesis.
3. **Use case monitoring yang belum lengkap.** Blind spot yang ditulis di handover detection (Day 14 bagian 2.7) dan teknik relevan tanpa rule.
4. **Hunt sebelumnya dan usulan L1.** Hipotesis baru di laporan hunt, dan usulan dengan templat L1 (Day 07 bagian 1.10).
5. **Purple team.** Teknik yang tidak terlihat atau tidak memicu saat latihan (bagian 1.7) menjadi entri baru.

Satu aturan mutu ditegakkan sejak Day 03: entri backlog tidak boleh hanya judul. Minimal ada hipotesis yang bisa dibantah, sumber yang konkret, dan Evidence yang dibutuhkan beserta kesiapannya. Entri tanpa itu bukan hipotesis, melainkan rasa penasaran.

Penilaian ulang adalah yang membuat backlog tetap berguna. Setiap Selasa pagi, 30 menit sebelum hunt dimulai, entri ditinjau: kesiapan data diperbarui, skor dihitung ulang, dan entri yang sudah tercakup hunt lain atau ternyata celah data ditutup atau dipindah ke register. Entri yang tidak dinilai ulang lebih dari 30 hari ditandai "perlu dinilai ulang", dan lebih dari 90 hari ditutup atau ditulis ulang. Angka 30 dan 90 adalah keputusan program, bukan standar.

Skor prioritas PT JAB sengaja sederhana, karena yang penting bukan ketepatan angkanya melainkan adanya alasan yang tertulis untuk urutan: Relevansi (0 sampai 3: pola insiden PT JAB atau area termahal bernilai 3), Celah (0 sampai 3: tidak pernah diburu dan tanpa detection bernilai 3), Kesiapan data (SIAP 2, SIAP SEBAGIAN 1, TIDAK SIAP 0), dan Biaya (0 bila muat satu hari hunting, minus 1 bila butuh lebih atau butuh orang lain). Skor ini rancangan program, bukan format TaHiTI. Penerapannya ke 23 entri PT JAB ada di bagian 2.2.

### 1.6 Kalender dan perlindungan waktu

Bagian kedua pertanyaan keempat Dimas adalah kalender. Panduan SANS menegaskan hunt dijadwalkan, bukan diimprovisasi, dan tim periodik memakai ritme mingguan, dua mingguan, atau bulanan [S1]. Ada dua ritme berbeda yang sering dicampur: hunt menjawab "apakah ada yang luput", sedangkan purple team menjawab "apakah detection dan telemetri yang kita punya benar-benar bekerja" (bagian 1.7). Tabel berikut adalah ritme PT JAB; baca kolom "Sumber angka", karena sebagian ritme berasal dari kerangka yang bisa dirujuk dan sebagian dari keputusan sendiri.

| Kegiatan | Ritme PT JAB | Keluaran | Sumber angka |
|---|---|---|---|
| Hunt terjadwal | Selasa dan Kamis | Satu laporan per hunt (Day 15 bagian 2.1) | Keputusan program; SANS menyebut mingguan sampai bulanan untuk tim periodik [S1] |
| Penilaian ulang backlog | Setiap Selasa pagi, 30 menit | Urutan dan kesiapan diperbarui | Keputusan program |
| Review usulan deteksi bersama Sari | Setiap Rabu, 30 menit (bukan hari hunting) | Keputusan per usulan | Keputusan program (bagian 1.8) |
| Latihan purple team | Bulanan, 5 sampai 10 teknik per sesi | Lembar hasil per teknik dan laporan lessons learned | PTEF: latihan mini bulanan 5 sampai 10 TTP, latihan penuh kuartalan [S9] |
| Laporan lessons learned purple | Kurang dari 2 minggu setelah sesi | Laporan ke Dimas dan pemilik | PTEF [S9] |
| Tinjauan program | Akhir kuartal | Metrik program dan kalender kuartal berikutnya dikunci | Keputusan program; tinjauan kuartalan juga dipakai [S1][S9] |
| Hari cadangan | Satu per bulan | Pengganti hari yang diambil, atau sisa pekerjaan | Keputusan program |

Dua hal membuat kalender bertahan. Pertama, tanggal dikunci satu kuartal di depan, termasuk hari cadangan, sehingga piket L2 bisa direncanakan sejak awal. Hari hunting yang jatuh pada libur nasional dipindah ke hari terdekat; Selasa 1 Juni (Hari Lahir Pancasila) dan Selasa 17 Agustus sudah pasti libur, sedangkan tanggal libur lain dan cuti bersama 2027 dicek di kalender resmi saat mengunci tanggal. Kedua, ada pemilik bernama di tingkat yang cukup tinggi: Dimas memutuskan setiap pengambilan hari hunting, dan Hendra menerima laporan kesehatan program bulanan. Tanpa itu, kegiatan hunt dan purple selalu kalah oleh insiden.

Kalender juga perlu campuran tipe hunt. PEAK membedakan hypothesis-driven, baseline (exploratory data analysis), dan model-assisted [S2]. Kalender yang hanya berisi hypothesis-driven melewatkan pembaruan baseline setelah perubahan telemetri (pelajaran Day 16 bagian 1.4); kalender yang hanya berisi baseline jarang menguji perilaku penyerang secara langsung.

Soal angka ritme di luar tabel, sumbernya lemah. Tulisan praktisi dan vendor menyebut ritme mingguan untuk hunt, bulanan untuk purple, 8 sampai 15 teknik per latihan, lessons learned dalam lima hari kerja, dan dua hunt terstruktur per bulan sebagai patokan minimum [S5]. Angka itu tidak berasal dari standar atau survei yang bisa diverifikasi, dan sebagian berbeda dengan PTEF (5 sampai 10 TTP per latihan bulanan, laporan kurang dari 2 minggu) [S9]. Perlakukan sebagai titik awal, catat dari mana angka yang akhirnya dipakai, lalu pantau trennya. Tren hari terlindungi yang menurun adalah peringatan dini tekanan kapasitas, dan itu lebih berguna daripada angka absolutnya.

### 1.7 Purple team dengan Atomic Red Team

Pertanyaan kelima Dimas datang dari Sari, dan tempatnya jelas setelah tujuan purple team dipisahkan dari hunt. PTEF (Purple Team Exercise Framework, SCYTHE, versi 4) mendefinisikan latihan purple team sebagai penilaian full-knowledge: peserta menyerang, mendeteksi, dan merespons bersama, dipimpin CTI yang memilih TTP, dan aktivitas serangan ditunjukkan serta dijelaskan saat terjadi [S9]. Itu berbeda dari red team rahasia dan berbeda dari hunt: tidak ada yang dicari, karena semua orang tahu apa yang dijalankan; yang diukur adalah apa yang terlihat.

Untuk PT JAB, purple team menutup dua kebutuhan program yang sudah tercatat:

- **Membuktikan 12 detection hasil hunt.** Semua detection diuji saat dibuat (Day 14 bagian 1.8), tetapi belum pernah diuji ulang setelah perubahan telemetri 22 Maret atau setelah dipakai sebulan. PTEF menyebut metrik validasi berkelanjutan seperti laju regresi detection [S9]: detection yang dulu memicu bisa berhenti memicu tanpa ada yang mengubahnya.
- **Uji positif untuk hunt negatif lama.** 19 dari 26 hasil negatif belum pernah dibuktikan dengan uji positif (bagian 2.1). Test yang menghasilkan telemetri pola hunt lama memberi bukti bahwa query hunt itu tidak buta, atau menunjukkan bahwa ia buta.

Langkah awal yang dianjurkan untuk tim yang baru mulai sederhana. Presentasi MITRE Center for Threat-Informed Defense (Crys Tan, Maret 2025) menyebut "baby steps": opsional memilih kelompok ancaman yang relevan, memilih TTP yang diminati, menjalankan atomic testing atas TTP itu, lalu mengerjakan detection atau prevention sesuai kebutuhan, dengan Atomic Red Team dan micro emulation plan sebagai sumber [S13]. Micro emulation plan di Adversary Emulation Library meniru perilaku gabungan yang muncul di banyak aktor (misalnya enumerasi Active Directory, exfiltrasi data, penghapusan log), tidak butuh red team, dan hanya boleh dipakai dengan otorisasi eksplisit sebelumnya [S12]. Halaman ATT&CK tentang adversary emulation menyebut ATT&CK sebagai bahasa bersama bagi red team untuk meniru ancaman tertentu, dan merujuk presentasi tentang pemakaian ATT&CK untuk purple teaming [S14].

Atomic Red Team adalah pustaka test deteksi yang dipetakan ke ATT&CK, dirancang supaya tim bisa menguji lingkungannya dengan cepat, portabel, dan bisa diulang; lisensinya MIT [S10]. Setiap test punya GUID yang tidak berubah walau nomor urut test di satu teknik bisa bergeser, sehingga laporan selalu mencatat GUID. Modul Invoke-AtomicRedTeam menjalankan test dan menyediakan pilihan yang penting untuk latihan yang bisa diaudit [S11]:

- `-TestGuids` untuk memilih test dengan GUID, `-GetPrereqs` untuk menyiapkan prasyarat, `-Cleanup` untuk membalik perubahan setelah test, dan `-TimeoutSeconds` (bawaan 120 detik; proses yang tidak selesai dihentikan paksa).
- Log eksekusi bawaan berbentuk CSV di folder temp (`Invoke-AtomicTest-ExecutionLog.csv`) dengan kolom waktu UTC dan lokal, teknik, nomor test, nama test, hostname, IP, username, GUID, ProcessId, dan ExitCode; `-ExecutionLogPath` memindahkannya. Logger Attire menulis JSON dan satu-satunya yang menyimpan input serta output perintah lengkap.
- Peringatannya eksplisit: test bisa meninggalkan sistem dalam keadaan tidak diinginkan, jadi pastikan punya izin dan pakai mesin uji yang mirip lingkunganmu dengan sensor yang berjalan [S11].

Alur per TTP di PTEF memberi struktur sesi [S9]: CTI menjelaskan aktor dan TTP; diskusi singkat menetapkan kontrol dan visibilitas yang diharapkan; red team menjalankan TTP dan membagikan indikator (host, waktu); blue team mencari bukti dan mencatat metrik; detection engineering boleh menyesuaikan logika saat itu juga lalu TTP dijalankan ulang. Blue team mencatat tingkat deteksi (alert, telemetri, kecocokan IOC, perilaku umum, perilaku spesifik), waktu deteksi dan investigasi, skor 0 sampai 5 (0 tanpa visibilitas, 3 alert muncul, 5 respons penuh; cek label nilai 1, 2, dan 4 di dokumen PTEF), dan kategori celah (visibilitas, logika detection, alert yang diredam, proses, ketepatan waktu) [S9]. Peran PTEF dipetakan ke PT JAB sebagai berikut: sponsor Dimas, koordinator latihan kamu, peran CTI dipegang kamu bersama Sari (memilih TTP dari insiden dan intel), "red team" kamu sendiri yang menjalankan test, dan blue team adalah L1 shift, L2 piket, dan Sari.

Satu keputusan perlu diambil Dimas dan Hendra: lab atau produksi. PTEF menganjurkan sistem produksi karena paling mencerminkan lingkungan dan menguji orang, proses, dan teknologi sekaligus, dengan syarat test diuji dulu di sistem serupa di luar latihan [S9]. PT JAB sejauh ini hanya menjalankan test di VM lab `jab-lab-win11` yang mengirim ke Splunk lab `jab-lab-splunk01` (Day 13 bagian 2.4). Lab menguji logika detection dan konfigurasi Sysmon, tetapi tidak menguji forwarder produksi, jadwal ES, atau triase L1. Usulan Day ini: sesi pertama di lab (tidak butuh persetujuan baru), lalu dua host uji di produksi untuk sesi berikutnya bila disetujui, yaitu `JKT-WS-0690` di OU `Workstations-EDR` (dengan Sysmon) dan `BDG-WS-0240` di OU Bandung (hanya 4688), dengan tiket change, akun uji terpisah, dan pemberitahuan ke L1 shift sebelum sesi. Dua host itu sengaja berbeda populasi, supaya latihan memperlihatkan perbedaan cakupan detection Sysmon dan 4688 (Day 16 bagian 1.4). Test cloud tidak dijalankan sama sekali tanpa otorisasi tertulis khusus, karena penyedia cloud punya kebijakan pengujian sendiri [S9].

### 1.8 Jalur hunt ke detection engineering

Pertanyaan keenam Dimas menyebut kasus nyata: usulan certutil dari `HUNT-2027-002` menunggu 43 hari sebelum aktif (Day 14 bagian 2.7). Day 14 sudah membuat bentuknya (abstract deteksi, Sigma, pipeline, uji, handover akhir) dan Day 15 membuat pelacakannya (`origin_hunt`, tanggal laporan, tanggal aktif). Yang belum ada adalah aturan program: siapa memutuskan, kapan, dan apa pilihannya. Panduan SANS meminta sinyal yang tervalidasi diubah menjadi detection dan waktu sampai operasional dilacak, tanpa memberi target [S1]; artikel metrik PEAK meminta detection ditautkan ke hunt asalnya supaya insiden dari detection hasil hunt bisa dihitung [S7].

Aturan yang diusulkan untuk PT JAB:

1. **Satu antrean.** Setiap usulan masuk sebagai issue berlabel `hunt-handover` di `jab-detections`, dengan file usulan di `jab-hunt/handover/`. Tidak ada usulan lewat chat.
2. **Satu format.** Templat tiket bagian 2.6, yang wajib memuat volume mentah dan setelah pengecualian, FP terkonfirmasi, cakupan jujur, dan uji positif.
3. **Satu ritme.** Review setiap Rabu 30 menit antara Sari dan hunter. Rabu dipilih karena bukan hari hunting dan bukan hari Sari menerima piket terberat.
4. **Satu tenggat.** Keputusan paling lambat 10 hari kerja setelah usulan masuk. Angka 10 hari kerja berasal dari tulisan praktisi, bukan standar [S5]; ia dipakai karena median laporan ke aktif 12 detection PT JAB adalah 8 hari kalender (Day 15 bagian 2.4), dan usulan yang masuk setelah repo dan format handover ada aktif dalam 6 sampai 8 hari.
5. **Lima keputusan sah.** Alert, sinyal risk, laporan hunter (bukan alert), tunda dengan syarat tertulis, atau tolak dengan alasan. Tunda dan tolak adalah hasil yang tercatat, bukan tiket yang mengendap.
6. **Anggaran antrean L1.** Tambahan alert dari detection hasil hunt dibatasi rata-rata 3 per minggu, angka yang disepakati di Day 14 bagian 2.1. Detection baru yang akan melewati anggaran hanya diaktifkan bila detection lain dituning atau diubah menjadi sinyal risk. Ini yang membuat Gilang dan Dwi tidak menjadi pihak yang membayar keberhasilan program.

Usulan yang lewat tenggat tidak otomatis disetujui. Ia dilaporkan ke Dimas di laporan kesehatan bulanan sebagai "menunggu lebih dari tenggat", karena yang perlu diperbaiki adalah kapasitas Sari, bukan aturannya. Hunter juga tidak mengaktifkan detection sendiri: role `jab_hunter` hanya ada di `jkt-splunk-sh01`, dan detection ES dipegang Sari di `jkt-splunk-es01` (Day 15 bagian 2.6). Pemisahan itu disengaja, karena reviewer detection harus orang lain selain pembuat usulan.

Jalur yang sama berlaku ke arah sebaliknya. Blind spot yang ditulis di handover detection, temuan purple team berkategori "logika detection", dan detection yang dimatikan karena FP kembali ke backlog sebagai entri baru (Day 14 bagian 1.9).

### 1.9 Metrik kesehatan program

Pertanyaan ketujuh Dimas punya dua lapis. Metrik outcome (detection aktif, insiden, celah ditutup, teknik yang diburu) sudah dibahas di Day 15 bagian 1.3 sampai 1.5; artikel metrik PEAK menyebut lima metrik kunci itu [S7], dan TaHiTI memberi daftar yang mirip: dwell time temuan, insiden yang dipicu hunting, use case monitoring yang ditambah atau diperbarui, intel baru, rekomendasi preventif, serta kerentanan dan miskonfigurasi yang ditemukan [S3]. Lapis yang ditambahkan Day ini adalah metrik kesehatan: ukuran proses yang memberi peringatan sebelum outcome turun. Metrik outcome menjawab "apakah program menghasilkan sesuatu"; metrik kesehatan menjawab "apakah program masih bisa menghasilkan sesuatu bulan depan".

Tabel berikut adalah metrik kesehatan PT JAB; baca kolom "Peringatan dini untuk", karena itulah alasan setiap metrik dipantau.

| Metrik kesehatan | Cara menghitung | Peringatan dini untuk |
|---|---|---|
| Hari terlindungi | Hari dialokasikan yang dipakai untuk pekerjaan program (hunt, purple, tinjauan), dibagi hari dialokasikan | Model hibrida sedang kalah oleh antrean |
| Porsi hari untuk hunt | Hari yang menjalankan hunt, dibagi hari dialokasikan | Program bergeser ke administrasi |
| Umur usulan tanpa keputusan | Hari sejak usulan masuk sampai keputusan, atau sampai hari ini bila belum | Jalur ke detection engineering macet |
| Umur backlog | Hari sejak entri terakhir dinilai ulang; jumlah entri per sumber | Backlog membusuk atau hanya memakan pertanyaannya sendiri |
| Hasil negatif teruji | Hunt negatif dengan uji positif, dibagi hunt negatif | "Tidak ditemukan" yang belum terbukti tidak buta |
| Beban L1 dari detection hunt | Alert per minggu dari detection hasil hunt, dibanding anggaran 3 per minggu | Program memindahkan biaya ke L1 |
| Ketergantungan satu orang | Hunt atau laporan hunter yang dijalankan orang selain hunter utama | Program berhenti saat satu orang tidak ada |

Dua metrik dari panduan SANS juga dipantau di tingkat program: delta cakupan ATT&CK dan perbaikan visibilitas [S1], yang di PT JAB sudah dihitung lewat layer Navigator dan register celah (Day 15 bagian 2.7 dan 2.8). Dampak pada dwell time, yang juga ada di daftar SANS [S1], sengaja tidak dijanjikan: dengan satu kompromi yang ditemukan saat hunt (`INC-2027-040`), PT JAB belum punya dasar untuk mengukurnya.

Yang sengaja tidak menjadi metrik kesehatan: jumlah hunt per hunter (merusak program [S8]), jumlah query, dan jumlah laporan. Jumlah hunt tetap dicatat sebagai konteks, karena PEAK menyebutnya ukuran seberapa keras tim bekerja, bukan dampak [S7].

### 1.10 Kriteria evaluasi ditetapkan di muka

Bagian akhir pertanyaan ketujuh Dimas ("kapan kita bilang berhasil") hanya bisa dijawab jujur bila jawabannya ditulis sekarang, sebelum angka Juli keluar. Kriteria yang ditulis setelah angka keluar cenderung menyesuaikan diri dengan angka itu, sama seperti abstract yang ditulis setelah hunt selesai (Day 01 bagian 2.1). Survei SANS 2026 mengaitkan turunnya pengukuran hasil hunting dengan sulitnya program mempertahankan anggaran dan keberadaannya [S15]; evaluasi Juli adalah momen itu bagi PT JAB.

Tiga keputusan yang mungkin, dengan logika yang ditulis di muka:

- **Lanjut.** Kriteria outcome terpenuhi (detection atau perbaikan detection baru aktif, celah ditutup atau keputusan anggaran diambil, hasil negatif Q2 teruji) dan kriteria proses tidak jauh di bawah ambang.
- **Ubah model.** Outcome ada, tetapi proses gagal: hari terlindungi di bawah ambang, jalur ke Sari macet, beban L1 melewati anggaran, atau program masih bergantung pada satu orang. Masalahnya bentuk, bukan nilai, sehingga yang diubah adalah model tim atau aturan, bukan programnya.
- **Hentikan atau bekukan.** Outcome tidak ada walaupun waktunya terlindungi (hunting dijalankan tetapi tidak mengubah apa pun), atau organisasi tidak mampu melindungi waktu sama sekali (hari terlindungi di bawah 60% dua bulan berturut-turut tanpa keputusan pengganti). Menghentikan program yang tidak menghasilkan perubahan adalah keputusan yang sah, dan laporan penghentiannya tetap mencatat celah dan baseline yang ditinggalkan.

Yang sengaja bukan kriteria: jumlah hunt, persentase hijau di heatmap ATT&CK, dan jumlah insiden yang ditemukan saat hunt. Insiden saat hunt bergantung pada apakah penyerang kebetulan aktif di area dan rentang yang diperiksa; PEAK menyebutnya indikator lemah karena hunter tidak mengendalikan aktivitas penyerang [S7]. Insiden dari detection hasil hunt dicatat dan dilaporkan, tetapi juga tidak dijadikan syarat, karena empat bulan terlalu pendek untuk menilainya. Ambang angka per indikator ada di bagian 2.8.

## 2. Contoh dan langkah praktis: rancangan program PT JAB untuk sisa percobaan

Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi. Query ditulis untuk Splunk PT JAB; lookup program (`jab_hunt_days.csv`, `jab_hunt_handover.csv`, `jab_hunt_backlog.csv`) adalah rancangan program, bukan format baku. Nomor `HUNT-2027-033` dan seterusnya di bagian ini adalah entri backlog dan kalender, bukan hasil hunt.

### 2.1 Angka program per 15 April

Semua jawaban untuk Dimas dimulai dari titik awal yang dihitung, bukan diingat. Lembar metrik 31 Maret (Day 16 Bagian G) ditambah empat hunt April (`-029` sampai `-032`), status register yang masuk sampai 14 April, dan hari hunting April. Tabel berikut hanya menampilkan baris yang dipakai Day ini; baca kolom "Cara membaca", karena beberapa angka turun dan itu jujur.

| Metrik | 31 Mar | 15 Apr | Cara membaca |
|---|---|---|---|
| Nomor hunt dibagikan | 28 | 32 | 29 selesai + 2 di nomor lain (`-003` sebagai `-021`, `-009` sebagai `-013`) + 1 kandidat (`-008`) |
| Hunt selesai | 25 | 29 | endpoint Windows 18 (termasuk `-032`, host dan jaringan POP), jaringan dan DNS 4, Linux 3, identitas 3 (`-018`, `-029`, `-030`), cloud 1 (`-031`) |
| Kategori hasil | 1 / 1 / 23 | 1 / 2 / 26 | ditemukan 1, ditemukan-bukan-insiden 2 (`-019`, `-030`), tidak-ditemukan 26 |
| Hasil negatif dengan uji positif | 5 dari 23 (21,7%) | 7 dari 26 (26,9%) | `-029` (sesi `INC-2027-001`) dan `-032` (PDFSuite dan deret sintetis) teruji; `-031` tanpa uji positif |
| Detection aktif lahir dari hunt | 12 dari 9 hunt | 12 dari 9 hunt | Tetap; usulan April masih menunggu keputusan |
| Rasio hunt ke detection | 9/25 = 36,0% | 9/29 = 31,0% | Turun karena penyebut naik; empat usulan April belum diputuskan |
| Usulan menunggu keputusan | 0 | 4 | Rule kredensial aplikasi (`-030`), laporan sesi lintas hari (`-029`), aksi baru AWS (`-031`), beacon firewall POP (`-032`); umur 7 sampai 9 hari |
| Laporan hunter terjadwal | 6 + VR mingguan | 6 + VR mingguan | Tiga usulan laporan April di baris sebelumnya |
| Teknik diburu (unik, v20) | 34 | 39 | +5: T1550.004, T1550.001, T1078.004, T1098.001, T1528 |
| Teknik ber-detection dari hunt | 15/34 (44,1%) | 15/39 (38,5%) | Turun; teknik identitas dan cloud baru diburu |
| Celah data | 20 dilaporkan, 3 ditutup + G03 sebagian, 17 berstatus | 22 dilaporkan, 3 ditutup + G03 sebagian, 19 berstatus | +2: G21 (sign-in service principal dan managed identity tidak diekspor), G22 (pemetaan IP ke host POP dari lease DHCP) |
| Miskonfigurasi | 17 dilaporkan, 4 diperbaiki | 20 dilaporkan, 4 diperbaiki | +3: M18 (`JAB-NOC-CapacityExport`, secret 687 hari, owner nonaktif; tenggat sertifikat 2027-05-19), M19 (`JAB-Survey-Connector` tanpa owner), M20 (`sourceIdentity` tidak diwajibkan) |
| Hari hunting dialokasikan | 17 | 22 | April: Kamis 1 (tindak lanjut evaluasi Q1), Selasa 6 dan Kamis 8 (hunt), Selasa 13 (piket menggantikan Yoga), Kamis 15 (menyusun usulan ini) |
| Hari menjalankan hunt | 14 | 16 | 16/22 = 72,7% |
| Alert L1 dari detection hunt | 0 (hari pertama) | 12 dalam 4 minggu | 3,0 per minggu, tepat di anggaran (bagian 2.7) |
| Hunt dipimpin orang selain kamu | 0 | 0 | Ketergantungan satu orang belum berkurang |

Penilaian HMM per 15 April: perilaku HMM2 terbukti, bukti awal HMM3 menguat, HMM4 belum (bagian 1.4).

**Kapan gagal:** angka April disusun dari ingatan karena laporan `-029` sampai `-032` belum diberi blok Metrik; atau hunt `-030` dimasukkan ke "tidak-ditemukan" karena "bukan insiden", padahal kategorinya ditemukan-bukan-insiden dan miskonfigurasinya masuk register.

### 2.2 Backlog yang dinilai ulang, dan templat entrinya

Bagian ini menjawab pertanyaan keempat Dimas dari sisi isi. Sebelum menyusun kalender, backlog dinilai ulang Kamis pagi ini, karena kalender yang disusun dari backlog yang belum dinilai akan menjadwalkan entri yang sudah tercakup hunt lain.

**Tujuan:** melihat umur setiap entri sejak terakhir dinilai, dan dari mana entri berasal.

**Sintaks:**

```
| inputlookup jab_hunt_backlog.csv
| where status="antre"
| eval asof=strptime("2027-04-15", "%Y-%m-%d")
| eval umur=round((asof - strptime(dinilai_ulang, "%Y-%m-%d")) / 86400, 0)
| eval kondisi=case(umur>90, "basi: tutup atau tulis ulang",
                    umur>30, "perlu dinilai ulang",
                    true(), "segar")
| stats count AS entri min(umur) AS umur_min max(umur) AS umur_maks BY kondisi
```

| Bagian | Fungsi |
|---|---|
| `inputlookup jab_hunt_backlog.csv` | Lookup ekspor `jab-hunt/backlog/BACKLOG.md` (kolom `entri`, `judul`, `sumber`, `dibuat`, `dinilai_ulang`, `status`, `kesiapan`, `skor`) |
| `where status="antre"` | Hanya entri yang belum dijadwalkan atau selesai |
| `eval asof=strptime("2027-04-15", ...)` | Tanggal acuan tetap, bukan `now()`, supaya hasil bisa dihitung ulang orang lain |
| `eval umur=...` | Hari sejak terakhir dinilai ulang |
| `case(umur>90, ..., umur>30, ...)` | Ambang 30 dan 90 hari dari aturan program (bagian 1.5) |

Keluaran ilustrasi:

```
kondisi                 entri  umur_min  umur_maks
perlu dinilai ulang     12     35        72
segar                   11     7         30
```

**Cara membaca hasil:** 23 entri, tidak ada yang basi, tetapi 12 entri tidak pernah dinilai ulang sejak dibuat, dua di antaranya sejak 2 Februari (72 hari). Kolom `dinilai_ulang` di semua entri sama dengan `dibuat`: penilaian ulang Selasa pagi yang ditetapkan untuk usulan L1 di Day 07 tidak pernah diterapkan ke entri hunter sendiri.

**Variasi:** ganti `BY kondisi` dengan `BY sumber` untuk melihat asal entri. Keluaran ilustrasinya: hunt lain 14, celah monitoring 5, insiden historis 2, celah data 1, keahlian domain 1. Intel tidak muncul sama sekali, karena `stats` tidak membuat baris untuk nilai yang tidak ada di data. Sejak brief forum intel ISP regional (Day 03), tidak ada satu entri pun dari intel, dan 14 dari 23 entri lahir dari hunt sebelumnya. Backlog sedang memakan pertanyaannya sendiri; rencana 90 hari menambahkan masukan intel bulanan (bagian 2.3).

**Kapan gagal:** status ditulis tidak seragam (`antre`, `Antre`, `queued`) sehingga `where` membuang entri; atau tanggal di `BACKLOG.md` ditulis `15/04/2027` sehingga `strptime` mengembalikan null dan `umur` kosong tanpa error.

Hasil penilaian ulang Kamis pagi dirangkum di tabel berikut. Skor memakai rumus bagian 1.5 (Relevansi + Celah + Kesiapan + Biaya). Baca kolom "Keputusan": entri dengan skor 6 ke atas dijadwalkan dan diberi nomor, sisanya tetap kandidat tanpa nomor, sesuai kebiasaan program sejak Day 02 bahwa nomor hunt diberikan saat dijadwalkan.

| Entri | Asal | ATT&CK (v20) | Kesiapan | Skor | Keputusan |
|---|---|---|---|---|---|
| Consent pengguna ke aplikasi pihak ketiga | Day 17, pola `INC-2026-021` | T1528 | SIAP (audit Entra 1 tahun) | 3+3+2+0 = 8 | `HUNT-2027-033`, Sel 20 Apr |
| Unduhan tahap kedua lewat PowerShell dan curl.exe | Day 02, celah `-002` | T1105, T1059.001 | SIAP (214 host) | 2+3+2+0 = 7 | `HUNT-2027-034`, Sel 27 Apr |
| Service baru dengan ImagePath di folder user-writable | Day 10 | T1543.003 | SIAP (7045 dari 391 host) | 2+3+2+0 = 7 | `HUNT-2027-035`, Kam 29 Apr |
| WMI permanent event subscription lintas fleet | Day 10 | T1546.003 | SIAP (Velociraptor 428 host) | 2+3+2+0 = 7 | `HUNT-2027-036`, Sel 11 Mei |
| Stacking ekstensi browser | Day 12, `BDG-WS-0196` | T1176.001 | SIAP SEBAGIAN | 3+3+1+0 = 7 | `HUNT-2027-037`, Kam 13 Mei (bahan keputusan allowlist Edge untuk Nina) |
| Pemanggil `listKeys` storage account | Day 17 | Ditetapkan saat abstract (cek ATT&CK v20) | SIAP SEBAGIAN (`index=azure`, field perlu dicek) | 3+3+1+0 = 7 | `HUNT-2027-038`, Sel 18 Mei |
| Autostart yang hilang di antara dua koleksi mingguan | Day 18 | T1053.005, T1547.001 | SIAP (koleksi Velociraptor mingguan) | 3+3+2-1 = 7 | `HUNT-2027-040`, Kam 27 Mei (notebook) |
| Koneksi keluar dari proses layanan 35 server Linux tanpa execve | Day 16 | T1071.001 | SIAP SEBAGIAN (firewall saja) | 3+3+1+0 = 7 | `HUNT-2027-041`, Kam 3 Jun |
| Side-load dari Program Files pihak ketiga | Day 16 | T1574.001 | SIAP (Velociraptor) | 3+2+2+0 = 7 | `HUNT-2027-044`, Sel 22 Jun |
| File `.js/.jse/.vbs/.wsf` di Downloads, Temp, Desktop host tanpa Sysmon | Day 13, pelajaran `INC-2026-019` | T1059.005, T1059.007 | SIAP (Velociraptor) | 3+2+2+0 = 7 | `HUNT-2027-045`, Kam 1 Jul (dipimpin Yoga) |
| 4698 diikuti 4699 untuk task yang sama dalam waktu singkat | Day 07 (kandidat bernomor) | T1053.005 | SIAP (kini juga 63 workstation regional) | 2+2+2+0 = 6 | `HUNT-2027-008`, Kam 22 Apr |
| Office memanggil perantara (cmd, PowerShell) lalu proxy binary | Day 14, blind spot detection | T1218, T1204.002 | SIAP | 2+2+2+0 = 6 | `HUNT-2027-039`, Sel 25 Mei |
| Alert P3 perlindungan endpoint berkumpul di satu host | Day 07, usulan Gilang, pelajaran `INC-2026-017` | Cek ID teknik di ATT&CK v20 | TIDAK SIAP (index dan retensi alert ES belum dicek) | 3+3+0+0 = 6 | `HUNT-2027-042`, Sel 15 Jun, bersyarat cek Evidence selesai sebelum 1 Jun (Sari dan Gilang) |
| Beacon ke tujuan berprevalence tinggi | Day 14 | T1071.001 | SIAP | 2+3+2-1 = 6 | `HUNT-2027-043`, Kam 17 Jun |
| Transfer BITS ke tujuan eksternal dari sisi layanan | Day 02 | T1105, T1197 | TIDAK SIAP (sumber job BITS belum ada) | 2+3+0+0 = 5 | Kandidat Q3 |
| Proses dengan parent tidak tercatat (`unknown`) | Day 06 | Execution | SIAP | 1+2+2+0 = 5 | Kandidat Q3 |
| Proxy binary lain dari Office (msiexec, cmstp, installutil, regasm) | Day 14 | T1218 | SIAP | 2+1+2+0 = 5 | Kandidat Q3 |
| rundll32 dengan lebih dari satu "dll," | Day 14 | T1218.011 | SIAP | 1+2+2+0 = 5 | Kandidat Q3 |
| Laptop POP tanpa sesi kantor lebih dari 30 hari | Day 18 | Di luar ATT&CK (kebersihan aset) | SIAP SEBAGIAN | 2+2+1+0 = 5 | Kandidat Q3 |
| First-seen per host untuk pasangan parent-child yang sudah dikenal | Day 06 | Execution | SIAP | 1+2+2-1 = 4 | Kandidat Q3 |
| Abstract deteksi akses LSASS dari image tidak lazim | Day 14 (dikembalikan Sari) | T1003.001 | SIAP | 2+1+2-1 = 4 | Kandidat Q3; dibahas bersama Sari di purple sesi 2 |
| Stacking argumen curl/wget di server ber-auditd | Day 08 | T1105 | SIAP | (tidak diskor) | Ditutup: tercakup `HUNT-2027-028` |
| Cakupan 64 workstation yang belum terjangkau Velociraptor | Day 09 | Celah data | (tidak diskor) | Ditutup dari backlog: dipindah ke register sebagai bagian G18 |

Urutan kalender tidak hanya mengikuti skor. Dua aturan tambahan dipakai: entri identitas dan cloud didahulukan karena itu arah Q2 yang disepakati di evaluasi Q1 (Day 16 Bagian H), dan entri yang cocok untuk hunter pendamping ditaruh di Kamis pagi Yoga.

Templat entri backlog berikut menggantikan templat lama, diisi dengan entri teratas. Field `kesiapan` dan `di_luar_cakupan` paling sering menyelamatkan waktu, karena memaksa pemeriksaan data sebelum hunt dijadwalkan.

```yaml
entri: HUNT-2027-033               # nomor diberikan saat dijadwalkan; kandidat tanpa nomor
judul: Pengguna memberi consent ke aplikasi pihak ketiga yang meminta izin baca surat atau berkas
asal: Day 17 (backlog), pola INC-2026-021
hipotesis: >
  Dalam 12 bulan terakhir ada akun PT JAB yang memberi consent ke aplikasi multi-tenant di luar
  katalog TI dengan izin delegated baca surat, berkas, atau offline_access, dan aplikasi itu
  kemudian dipakai dari luar jaringan PT JAB tanpa ada yang meninjau.
able:
  actor: tidak spesifik (pola phishing consent)
  behavior: T1528 Steal Application Access Token
  location: tenant Entra jab.example, semua akun pengguna
  evidence: audit Entra di index=o365 (1 tahun), aktivitas consent; inventaris enterprise app
kesiapan: SIAP (nama aktivitas audit consent dicek di referensi audit sebelum query ditulis)
di_luar_cakupan: consent oleh admin tenant atas nama organisasi; aplikasi yang dibuat di tenant sendiri
kriteria_sukses: setiap consent ke aplikasi di luar katalog diberi label jinak / perlu investigasi / data tidak cukup
fp_diduga: add-in Outlook resmi, aplikasi rapat vendor, integrasi CRM tim sales
time_box: satu hari (Selasa 2027-04-20)
handover: IR (Dimas) bila ditemukan; Lutfi untuk kebijakan consent; Sari untuk usulan deteksi
skor: 8 (relevansi 3, celah 3, kesiapan 2, biaya 0)
sumber: insiden historis
dibuat: 2027-04-06
dinilai_ulang: 2027-04-15
status: terjadwal
```

### 2.3 Rencana 90 hari: Kamis 15 April sampai Kamis 15 Juli 2027

Rencana ini menjawab permintaan Dimas akan "rencana 90 hari". Panduan SANS membagi program baru menjadi tiga fase tanpa durasi: fondasi, eksekusi dan kodifikasi, serta pelembagaan dan perluasan [S1]. PT JAB sudah melewati sebagian besar fondasi di Q1, sehingga 90 hari ini berfokus pada kodifikasi dan pelembagaan; pembagian minggu di tabel adalah rancangan sendiri. Baca kolom "Bukti selesai", karena itulah yang diperiksa saat evaluasi Juli.

| Fase | Tanggal | Pekerjaan | Bukti selesai |
|---|---|---|---|
| 0. Mengunci | Kam 15 Apr sampai Rab 21 Apr | Aturan perlindungan disetujui Dimas; kalender Q2 dan Juli dikunci, termasuk jadwal pendamping Yoga dan piket; kriteria evaluasi Juli ditandatangani Dimas dan dikirim ke Hendra; lookup `jab_hunt_days.csv` dan `jab_hunt_handover.csv` dibuat dan diisi mundur sejak 2 Februari; review Rabu pertama dengan Sari (21 April) memutuskan empat usulan April | Dokumen `jab-hunt/docs/program-2027-Q2.md`; empat usulan April punya keputusan |
| 1. Menguji yang sudah ada | Sel 20 Apr sampai Kam 20 Mei | Hunt identitas dan cloud (`-033`, `-038`) dan dua entri lama (`-008`, `-034`); purple sesi 1 di lab (6 Mei) untuk 12 detection hasil hunt; usulan host uji produksi ke Dimas dan Agung; laporan lessons learned sesi 1 paling lambat Kamis 20 Mei; masukan intel pertama ke backlog (brief forum ISP regional atau laporan publik terbaru) | Lembar hasil purple sesi 1; laporan lessons learned; minimal satu entri backlog bersumber intel |
| 2. Menutup celah dan mengodifikasi | Sel 25 Mei sampai Kam 24 Jun | Hunt `-039` sampai `-044`; purple sesi 2 (10 Jun) untuk uji positif hunt negatif lama, di host uji bila disetujui; detection atau laporan hunter dari hunt fase 1 diputuskan sesuai tenggat; tinjauan bulanan ke Hendra | Semua hunt negatif fase 1 dan 2 punya uji positif; usulan dari fase 1 punya keputusan dalam 10 hari kerja |
| 3. Melembagakan | Sel 29 Jun sampai Kam 15 Jul | Tinjauan kuartal Q2 (29 Jun) dan kalender Q3 dikunci; hunt `-045` dipimpin Yoga; purple sesi 3 (8 Jul) sebagai uji regresi; playbook program `jab-hunt/docs/playbook.md` (peran, ritme, cakupan, kebutuhan data, templat laporan); angka dibekukan Kamis 15 Jul | Playbook; satu hunt dipimpin orang lain; lembar metrik per 15 Jul |

Sesudah 15 Juli, dua minggu dipakai untuk menyusun evaluasi: Selasa 20 dan Kamis 22 Juli menyusun lembar metrik dan laporan lessons learned sesi 3, Selasa 27 Juli menyiapkan presentasi, dan evaluasi akhir percobaan berlangsung Rabu 2027-07-28 di depan Hendra dan Dimas.

Dua jalur awal yang disarankan panduan SANS untuk program baru adalah penyalahgunaan identitas istimewa dan lateral movement lewat alat administrasi jarak jauh [S1]. PT JAB sudah memburu jalur kedua di Q1 (`HUNT-2027-019`); jalur pertama baru disentuh di April. Itu sebabnya `-033` dan `-038` ada di fase 1.

**Kapan gagal:** rencana menjanjikan jumlah hunt ("14 hunt dalam 90 hari") alih-alih bukti selesai; atau fase 0 dilewati karena terasa administratif, sehingga kriteria evaluasi baru ditulis Juli setelah angkanya terlihat.

### 2.4 Kalender Q2 dan Q3

Kalender ini menjawab bagian kedua pertanyaan keempat Dimas dan menjadi dasar piket L2 sampai Juli. Kalender dikunci sampai 29 Juli; Agustus dan September hanya kerangka, karena bergantung pada keputusan evaluasi.

```
KALENDER PROGRAM HUNT PT JAB, 20 APRIL - 29 JULI 2027 (dikunci Rabu 2027-04-21)
Setiap Selasa 08:00-08:30: penilaian ulang backlog. Setiap Rabu: review usulan bersama Sari (30 menit).
Y = Yoga ikut sebagai hunter pendamping 08:00-12:00 (piket pagi itu: Sari dan Rudi)

Minggu  Tanggal      Kegiatan                                                        Catatan
16      Sel 20 Apr   HUNT-2027-033 consent aplikasi pihak ketiga (T1528)             identitas
        Kam 22 Apr   HUNT-2027-008 4698 lalu 4699 dalam waktu singkat (T1053.005)    kini + regional
17      Sel 27 Apr   HUNT-2027-034 unduhan lewat PowerShell dan curl (T1105)
        Kam 29 Apr   HUNT-2027-035 service ImagePath user-writable (T1543.003)       Y
18      Sel 04 Mei   Persiapan purple sesi 1: daftar test, uji kering di lab
        Kam 06 Mei   PURPLE SESI 1 (lab): 12 detection hasil hunt                    lessons learned <= 20 Mei
19      Sel 11 Mei   HUNT-2027-036 WMI subscription lintas fleet (T1546.003)
        Kam 13 Mei   HUNT-2027-037 ekstensi browser (T1176.001)                      Y
20      Sel 18 Mei   HUNT-2027-038 pemanggil listKeys storage                       cloud
        Kam 20 Mei   CADANGAN + laporan lessons learned sesi 1
21      Sel 25 Mei   HUNT-2027-039 Office -> perantara -> proxy binary (T1218)
        Kam 27 Mei   HUNT-2027-040 autostart hilang antar koleksi (notebook)         Y; tinjauan bulanan
22      Sel 01 Jun   LIBUR NASIONAL (Hari Lahir Pancasila)
        Kam 03 Jun   HUNT-2027-041 proses layanan Linux keluar (T1071.001)
23      Sel 08 Jun   Persiapan purple sesi 2
        Kam 10 Jun   PURPLE SESI 2: uji positif hunt negatif lama                    Y; host uji bila disetujui
24      Sel 15 Jun   HUNT-2027-042 alert P3 perlindungan berkumpul                   Gilang ikut; bersyarat
        Kam 17 Jun   HUNT-2027-043 beacon ke tujuan berprevalence tinggi
25      Sel 22 Jun   HUNT-2027-044 side-load dari Program Files pihak ketiga (T1574.001)
        Kam 24 Jun   CADANGAN + laporan lessons learned sesi 2                       Y
26      Sel 29 Jun   TINJAUAN KUARTAL Q2: metrik per 30 Jun, kalender Q3 dikunci
        Kam 01 Jul   HUNT-2027-045 file skrip di folder pengguna (VR)                dipimpin Yoga
27      Sel 06 Jul   Persiapan purple sesi 3
        Kam 08 Jul   PURPLE SESI 3: regresi detection + populasi regional            Y
28      Sel 13 Jul   CADANGAN
        Kam 15 Jul   PEMBEKUAN ANGKA (akhir 90 hari)
29      Sel 20 Jul   Menyusun lembar metrik evaluasi
        Kam 22 Jul   Menyusun evaluasi + lessons learned sesi 3
30      Sel 27 Jul   Persiapan presentasi
        Rab 28 Jul   EVALUASI AKHIR PERCOBAAN (Hendra, Dimas)
        Kam 29 Jul   Keputusan evaluasi masuk backlog dan kalender

KERANGKA AGUSTUS - SEPTEMBER (hanya bila diputuskan lanjut; tanpa nomor hunt)
- Kandidat Q3 dari backlog (bagian 2.2), ditambah entri dari purple sesi 1-3
- Purple sesi bulanan Kam 12 Agu dan Kam 09 Sep; Sel 17 Agu libur nasional
- Tinjauan kuartal Q3 Sel 28 Sep
```

**Cara membaca kalender:** dari 26 hari hunting antara 20 April dan 15 Juli, 14 dipakai hunt, 6 untuk purple (3 persiapan, 3 sesi), 3 cadangan, 1 tinjauan kuartal, 1 pembekuan angka, dan 1 libur. Purple team memakan hampir seperempat hari hunting; itulah harga yang dibayar untuk mengubah "tidak ditemukan" menjadi hasil yang teruji, dan harga itu ditulis di satu halaman untuk Hendra (bagian 2.9). Yoga ikut enam kali sebelum memimpin `-045`, jadi piket pagi dua orang terjadi enam Kamis dan sudah diketahui sejak April.

**Variasi:** bila Hendra menolak host uji produksi, sesi 2 dan 3 tetap di lab; yang hilang adalah uji forwarder, jadwal ES, dan triase L1, dan kekurangan itu ditulis di lembar hasil purple sebagai batas cakupan.

**Kapan gagal:** hari cadangan dipakai untuk hunt tambahan sejak awal, sehingga hari yang diambil insiden tidak punya pengganti; atau kalender dikunci tanpa piket L2 ikut disusun, sehingga Kamis pagi pendamping baru ketahuan bertabrakan dengan cuti Rudi.

### 2.5 Purple sesi 1: menguji 12 detection hasil hunt di lab

Rancangan ini menjawab pertanyaan kelima Dimas secara konkret. Sesi 1 dijalankan Kamis 2027-05-06 di VM lab `jab-lab-win11` (jaringan lab SOC terisolasi, snapshot bersih, Sysmon dengan profil `Workstations-EDR`) yang mengirim ke `jab-lab-splunk01`. Salinan detection dari `jab-detections` dijadwalkan Sari di Splunk lab memakai hasil konversi pipeline yang sama dengan produksi, sehingga yang diuji adalah logika dan telemetri, bukan pipeline produksi. Tidak ada test yang dijalankan di host PT JAB pada sesi ini.

Tabel berikut memetakan setiap detection ke cara mengujinya. Baca kolom "Cara uji", karena tidak semua detection bisa diuji dengan Atomic, dan yang tidak bisa ditulis apa adanya.

| Detection (hunt asal) | Cara uji | Hasil yang diharapkan |
|---|---|---|
| certutil atau bitsadmin mengunduh dari URL eksternal (`-002`) | Atomic T1105 test 7 sampai 9 (GUID dicocokkan di katalog saat persiapan) | Alert |
| Scheduled task menjalankan biner dari AppData (`-015`) | Atomic T1053.005 test 2 (Day 07), task diarahkan ke biner di AppData uji | Alert |
| Logon akun admin ke workstation dari selain `JKT-JUMP01` (`-019`) | Uji manual: akun admin uji lab logon jaringan dari VM lab kedua (cek ketersediaan VM kedua) | Alert |
| Office meluncurkan signed proxy binary (`-023`) | Atomic T1204.002 test 3 (`0330a5d2-a45a-4272-a9ee-e364411c4b18`) dan harness T1218.011 test 2 (Day 14) | Alert |
| Proxy binary dengan scriptlet atau skrip inline (`-023`) | Atomic T1218.010 test 1 (`449aa403-...`), T1218.005 test 2 (`906865c3-...`) dan test 10 (`8707a805-...`) | Alert |
| Script host dari Downloads, Temp, atau ekstraksi arsip (`-025`) | Atomic T1059.007 test 2 (`0709945e-4fec-4c49-9faf-c3c292a74484`), skrip disalin ke Downloads dulu (Day 13 bagian 3) | Alert |
| Office memunculkan shell (risk, `-001`) | Ikut test T1204.002 test 3 | Intermediate finding skor 20 |
| Beacon ke domain baru, unggahan besar ke tujuan baru, dan pengumpul dua sinyal (`-020`, `-022`) | Tidak dengan Atomic: replay data proxy seperti Day 14 bagian 2.5 | Risk event dan finding pengumpul pada data replay |
| Wazuh 100200 dan 100201 (`-010`) | Tidak dengan Atomic sampai ada VM Linux lab ber-agent: `wazuh-logtest` dengan event fixture (Day 08 bagian 2.8) | Rule cocok di logtest; dicatat sebagai uji logika saja |

Perintah untuk setiap test Atomic dijalankan di PowerShell admin di VM lab, setelah modul Invoke-AtomicRedTeam terpasang. Satu contoh untuk test pertama:

```powershell
# Di jab-lab-win11 (lab terisolasi), Kamis 2027-05-06. Bukan di host PT JAB.
Invoke-AtomicTest T1204.002 -TestGuids 0330a5d2-a45a-4272-a9ee-e364411c4b18 -ShowDetails
Invoke-AtomicTest T1204.002 -TestGuids 0330a5d2-a45a-4272-a9ee-e364411c4b18 -CheckPrereqs
Invoke-AtomicTest T1204.002 -TestGuids 0330a5d2-a45a-4272-a9ee-e364411c4b18 -GetPrereqs
Invoke-AtomicTest T1204.002 -TestGuids 0330a5d2-a45a-4272-a9ee-e364411c4b18 `
    -ExecutionLogPath C:\purple\2027-05-06\exec.csv -TimeoutSeconds 300
Invoke-AtomicTest T1204.002 -TestGuids 0330a5d2-a45a-4272-a9ee-e364411c4b18 -Cleanup
```

| Bagian | Fungsi |
|---|---|
| `-TestGuids` | Memilih test dengan GUID yang tetap, bukan nomor urut yang bisa bergeser [S11] |
| `-ShowDetails` | Menampilkan isi test sebelum dijalankan; baca dulu apa yang akan dilakukan |
| `-CheckPrereqs` / `-GetPrereqs` | Memeriksa dan menyiapkan prasyarat (misalnya dokumen Office uji); prasyarat yang mengunduh diambil sebelum VM diputus dari internet |
| `-ExecutionLogPath` | Menyimpan log eksekusi CSV per sesi; kolom waktu UTC dan lokal, hostname, username, dan GUID dipakai untuk mencocokkan dengan telemetri [S11] |
| `-TimeoutSeconds 300` | Menaikkan batas dari 120 detik bawaan karena Office lambat membuka dokumen pertama kali |
| `-Cleanup` | Membalik perubahan test; snapshot tetap dikembalikan setelah sesi |

Setelah semua test, log eksekusi diunggah ke Splunk lab sebagai lookup `jab_purple_2027_05_06.csv`, lalu dicocokkan dengan telemetri di sekitar setiap test.

**Tujuan:** memastikan setiap test menghasilkan telemetri di host dan jendela waktu yang tercatat, sebelum menilai apakah detection memicu.

**Sintaks (di `jab-lab-splunk01`):**

```
| inputlookup jab_purple_2027_05_06.csv
| eval t0=strptime('Execution Time (UTC)', "%Y-%m-%dT%H:%M:%SZ"), t1=t0+300
| map maxsearches=30 search="search index=sysmon host=$Hostname$ earliest=$t0$ latest=$t1$ | stats count AS sysmon_events dc(EventCode) AS jenis_event | eval Technique=\"$Technique$\", GUID=\"$GUID$\""
| table Technique GUID sysmon_events jenis_event
```

| Bagian | Fungsi |
|---|---|
| `'Execution Time (UTC)'` | Nama kolom log bawaan yang mengandung spasi, karena itu ditulis dalam tanda kutip tunggal di `eval` |
| `strptime(..., "%Y-%m-%dT%H:%M:%SZ")` | Format waktu ini adalah asumsi; cek satu baris log CSV di lab dan sesuaikan format sebelum dipakai |
| `t1=t0+300` | Jendela lima menit setelah test, sesuai `-TimeoutSeconds` |
| `map maxsearches=30 search="..."` | Menjalankan satu search kecil per baris log, dengan `$Hostname$`, `$t0$`, `$t1$` diganti nilai baris itu |
| `earliest=$t0$ latest=$t1$` | Rentang dalam epoch, jadi tidak bergantung zona waktu tampilan akun (pelajaran Day 18 bagian 1.6) |

Keluaran ilustrasi tidak ditulis di sini, karena sesi 1 belum berlangsung. Lembar hasil per test diisi saat sesi dan memakai kolom berikut:

```
Waktu WIB | Host | Teknik | GUID | Detection yang diharapkan | Telemetri (index, jumlah event) |
Alert/risk (ya/tidak, jam) | Triase (siapa, menit, keputusan) | Skor PTEF 0-5 |
Kategori celah (visibilitas | logika detection | alert diredam | proses | ketepatan waktu) | Tindak lanjut
```

**Cara membaca hasil (saat sesi):** baris dengan telemetri nol berarti masalah visibilitas atau konfigurasi Sysmon lab, bukan detection; jangan dinilai sebagai detection gagal. Baris dengan telemetri ada tetapi tanpa alert adalah celah logika atau pengecualian yang terlalu lebar, dan masuk backlog atau antrean Sari sebagai perbaikan detection lama, yang dihitung PEAK sama berharganya dengan detection baru [S7].

**Variasi:** di sesi 3, log eksekusi yang sama dijalankan ulang tanpa perubahan untuk mengukur regresi: detection yang memicu di sesi 1 tetapi tidak di sesi 3.

**Kapan gagal:** test dijalankan tanpa log eksekusi, sehingga waktu persisnya hanya diingat; atau `-Cleanup` dilewati dan test berikutnya berjalan di atas sisa test sebelumnya, sehingga telemetri tercampur.

### 2.6 Templat tiket hunt ke deteksi, dan contoh dari `HUNT-2027-030`

Templat ini adalah jawaban pertanyaan keenam Dimas dalam bentuk dokumen. Ia menggabungkan abstract deteksi Day 14 dengan baris program (tanggal masuk, tenggat, keputusan), dan contoh terisinya memakai usulan nyata yang sedang menunggu: rule kredensial aplikasi dari `HUNT-2027-030` (Day 17 bagian 2.8).

```
Judul         : [HUNT->DET] Kredensial ditambahkan ke aplikasi atau service principal
Asal          : HUNT-2027-030 (ditemukan-bukan-insiden), laporan Selasa 2027-04-06 14:30
Hipotesis     : Penambahan secret atau sertifikat ke app registration atau service principal
                adalah langkah T1098.001 yang murah dijaga, karena volume rendah dan tiap event
                bisa ditanyakan ke pelakunya
ATT&CK (v20)  : T1098.001
Bukti         : audit Entra 6 Apr 2026 - 6 Apr 2027: 58 event "Update application - Certificates
                and secrets management" (21 aplikasi, 6 pelaku), 0 "Add service principal
                credentials"; contoh yang ditinjau: JAB-NOC-CapacityExport, JAB-Survey-Connector
Mengapa rule  : Sekitar 1 per minggu; setiap event butuh satu pertanyaan ke pelaku; pola ini tidak
                punya detection sama sekali (layer awal Q1)
Usulan logika : index=o365 audit, activity berisi salah satu dari dua nama aktivitas di atas
Sumber data   : index=o365 (Entra audit), retensi 1 tahun; cakupan seluruh tenant
FP diketahui  : Rotasi terjadwal oleh DevOps (Lutfi, Tari) dan Infrastruktur dengan tiket;
                pengecualian per pelaku dan jam kerja sengaja tidak dipakai
Bentuk diusulkan: Alert ES, urgensi sedang
Dampak antrean L1: sekitar 1 per minggu, masuk anggaran 3 per minggu (12 alert dalam 4 minggu
                terakhir; total akan sekitar 4 per minggu, jadi butuh satu tuning, lihat Keputusan)
Uji           : Positif: replay salah satu dari 58 event audit di rentang hunt (rotasi secret
                bertiket oleh DevOps); negatif: data 1-14 Apr 2027
Pemilik       : Sari Kusuma (konten); <kamu> (hunter asal); review: Dimas Prasetyo
Masuk antrean : Selasa 2027-04-06 (issue hunt-handover di jab-detections)
Tenggat keputusan: Selasa 2027-04-20 (10 hari kerja)
Keputusan     : alert | risk | laporan hunter | tunda (syarat: ...) | tolak (alasan: ...)
Tanggal keputusan: (diisi Sari)
Tanggal aktif : (diisi Sari bila aktif)
```

Cara membaca elemennya:

- **Mengapa rule** memaksa pembedaan yang sering dilewati: tidak semua temuan hunt layak menjadi alert. Tiga usulan lain dari April justru berbentuk laporan hunter, karena volumenya akan menjadi tiket jinak setiap minggu (Day 17 bagian 2.8).
- **FP diketahui** adalah nilai terbesar yang dibawa hunter ke detection engineer, karena kasusnya sudah diperiksa satu per satu saat hunt.
- **Dampak antrean L1** menghitung ulang anggaran sebelum diaktifkan. Detection ini akan membawa total ke sekitar 4 per minggu, sehingga keputusan "alert" hanya sah bila Sari sekaligus menyetujui satu tuning yang menurunkan volume detection lain, misalnya scheduled task AppData di populasi regional (bagian 2.7).
- **Keputusan** ditulis sebagai lima pilihan sah. Tunda dan tolak wajib menyertakan syarat atau alasan, supaya usulan tidak kembali tanpa jejak.
- **Tenggat keputusan** dihitung dari tanggal masuk antrean, bukan dari tanggal review berikutnya, sehingga usulan yang masuk sehari setelah review tidak otomatis kehilangan satu minggu.

**Kapan gagal:** tiket dikirim tanpa baris dampak antrean L1, lalu tiga detection aktif dalam satu minggu dan antrean Gilang naik dua kali lipat tanpa ada yang memutuskannya; atau kolom keputusan dibiarkan kosong setelah review karena "masih dipikirkan", sehingga umur usulan terus naik tanpa tercatat sebagai tunda.

### 2.7 Melacak kesehatan program dengan tiga query

Query di bagian ini adalah alat untuk pertanyaan ketujuh Dimas: tiga angka kesehatan yang dihitung dari lookup program, dengan tanggal acuan tetap.

**Query 1: hari terlindungi.**

**Tujuan:** menghitung berapa hari hunting yang benar-benar dipakai untuk program, per periode.

```
| inputlookup jab_hunt_days.csv
| eval d=strptime(date, "%Y-%m-%d")
| where d>=strptime("2027-02-01", "%Y-%m-%d") AND d<strptime("2027-04-16", "%Y-%m-%d")
| eval periode=if(d<strptime("2027-04-01", "%Y-%m-%d"), "Q1 (1 Feb - 31 Mar)", "Q2 (1 - 15 Apr)")
| stats count AS dialokasikan
        count(eval(used_for="hunt")) AS hunt
        count(eval(in(used_for, "purple", "program"))) AS kerja_program
        count(eval(in(used_for, "piket", "insiden", "lain"))) AS diambil
        BY periode
| eval porsi_program=round(100 * (hunt + kerja_program) / dialokasikan, 1)
| eval porsi_hunt=round(100 * hunt / dialokasikan, 1)
```

| Bagian | Fungsi |
|---|---|
| `jab_hunt_days.csv` | Satu baris per hari hunting yang dialokasikan: `date`, `used_for` (`hunt`, `purple`, `program`, `piket`, `insiden`, `lain`), `keputusan_oleh`, `catatan` |
| `where d>=... AND d<...` | Rentang absolut; batas atas 16 April supaya 15 April ikut |
| `count(eval(used_for="hunt"))` | Menghitung baris yang memenuhi kondisi, idiom `stats` yang umum |
| `in(used_for, ...)` | Fungsi `in()` di dalam eval, bukan operator `IN`, supaya tidak bergantung versi |
| `porsi_program`, `porsi_hunt` | Dua metrik kesehatan dari bagian 1.9 |

Keluaran ilustrasi:

```
periode               dialokasikan  hunt  kerja_program  diambil  porsi_program  porsi_hunt
Q1 (1 Feb - 31 Mar)   17            14    3              0        100.0          82.4
Q2 (1 - 15 Apr)       5             2     2              1        80.0           40.0
```

**Cara membaca hasil:** Q1 tidak pernah kehilangan hari; tiga hari non-hunt (9 Februari kesiapan data, 16 Maret hunt ke deteksi, 18 Maret metrik) adalah pekerjaan program. April dalam dua minggu sudah kehilangan satu hari ke piket, dan porsi hunt 40% karena dua hari lain dipakai tindak lanjut evaluasi dan usulan ini. Lima hari terlalu sedikit untuk tren, tetapi cukup untuk menunjukkan bahwa satu hari yang diambil di bulan pendek langsung terasa.

**Kapan gagal:** hari yang diambil tidak dicatat sama sekali karena "cuma sekali", sehingga lookup hanya berisi hari yang dipakai dan porsi selalu 100%.

**Query 2: umur usulan ke detection engineering.**

**Tujuan:** melihat berapa lama usulan menunggu keputusan, dipisah menurut status.

```
| inputlookup jab_hunt_handover.csv
| eval asof=strptime("2027-04-15", "%Y-%m-%d")
| eval t_lapor=strptime(laporan, "%Y-%m-%d"), t_putus=strptime(diputuskan, "%Y-%m-%d")
| eval hari=round((coalesce(t_putus, asof) - t_lapor) / 86400, 0)
| eval status=case(keputusan="aktif", "aktif",
                   keputusan="tunda", "tunda dengan syarat",
                   keputusan="tolak", "ditolak",
                   keputusan="backlog", "kembali ke backlog",
                   true(), "menunggu keputusan")
| stats count AS usulan median(hari) AS median_hari max(hari) AS maks_hari BY status
```

| Bagian | Fungsi |
|---|---|
| `jab_hunt_handover.csv` | Satu baris per usulan: `id`, `origin_hunt`, `bentuk`, `laporan` (tanggal laporan hunt), `diputuskan`, `keputusan`, `aktif` |
| `coalesce(t_putus, asof)` | Usulan yang belum diputuskan dihitung sampai 15 April |
| `case(...)` | Lima status sesuai keputusan sah di bagian 1.8 |

Keluaran ilustrasi:

```
status                 usulan  median_hari  maks_hari
aktif                  18      8            43
kembali ke backlog     1       13           13
ditolak                1       13           13
menunggu keputusan     4       9            9
tunda dengan syarat    4       6            27
```

**Cara membaca hasil:** 28 usulan sejak Februari. Yang aktif (12 detection dan 6 laporan hunter) punya median 8 hari dari laporan ke keputusan, tetapi maksimum 43 hari (certutil) menunjukkan jembatan lama sebelum Maret. Empat usulan April menunggu 7 sampai 9 hari kalender, masih di dalam tenggat 10 hari kerja (sekitar 14 hari kalender), tetapi akan lewat tenggat Selasa 20 April bila review Rabu 21 April tidak memutuskannya. Satu usulan tunda (LogonType Password dari `-004`) diputuskan 27 hari setelah laporannya, karena laporan 18 Februari baru masuk triase Day 14.

**Kapan gagal:** usulan yang digabung (`related: merged`, seperti usulan `-004` dan `-015`) dihitung dua kali; atau tanggal keputusan diisi tanggal aktif, sehingga usulan yang disetujui tetapi menunggu jendela change tampak "menunggu".

**Query 3: beban L1 dari detection hasil hunt (dijalankan Sari di `jkt-splunk-es01`).**

**Tujuan:** membandingkan alert dari detection hasil hunt dengan anggaran 3 per minggu.

```
index=notable earliest="03/17/2027:09:00:00" latest="04/14/2027:09:00:00"
| stats count AS findings BY search_name
| append [| inputlookup jab_hunt_detections.csv | fields search_name origin_hunt]
| stats sum(findings) AS findings values(origin_hunt) AS origin_hunt BY search_name
| where isnotnull(origin_hunt)
| fillnull value=0 findings
| eventstats sum(findings) AS total
| eval per_minggu=round(total / 4, 1)
| sort - findings
```

Query ini sama dengan Day 15 bagian 2.6, dengan rentang empat minggu penuh dan dua baris tambahan: `eventstats` menjumlahkan semua finding, dan `per_minggu` membaginya dengan empat minggu.

Keluaran ilustrasi (nama detection disingkat):

```
search_name                                                  origin_hunt       findings  total  per_minggu
JAB - Scheduled task menjalankan biner dari folder AppData   HUNT-2027-015     9         12     3.0
JAB - Script host menjalankan skrip dari Downloads, Temp...  HUNT-2027-025     2         12     3.0
JAB - certutil atau bitsadmin mengunduh dari URL eksternal   HUNT-2027-002     1         12     3.0
JAB - Logon akun admin ke workstation dari selain JKT-JUMP01 HUNT-2027-019     0         12     3.0
JAB - Office meluncurkan signed proxy binary                 HUNT-2027-023     0         12     3.0
JAB - Proxy binary dengan scriptlet atau skrip inline        HUNT-2027-023     0         12     3.0
JAB - Dua sinyal risk berbeda pada satu entitas dalam 7 hari HUNT-2027-020,... 0         12     3.0
```

**Cara membaca hasil:** 12 alert dalam empat minggu, semuanya jinak setelah triase, tidak ada insiden. Sembilan berasal dari detection scheduled task AppData, dan lima di antaranya dari 63 workstation regional yang baru terlihat setelah GPO 22 Maret, sesuai peringatan Day 16 Bagian D bahwa detection ini akan melihat populasi baru. Program sudah tepat di anggaran, sehingga detection berikutnya hanya bisa aktif bila detection ini dituning. Itu bukan alasan menahan usulan; itu alasan menaruh tuning detection AppData di review Rabu 21 April. Wazuh 100200 dan 100201 dihitung terpisah di Dashboard dan masih 0 alert.

**Kapan gagal:** nama index penyimpan finding di ES 8.x berbeda dengan `notable` (Day 15 bagian 2.6 mencatat bahwa dokumentasi findings ES 8.7 tidak menyebutnya); cek di ES-mu sebelum memakai angka ini.

### 2.8 Kriteria evaluasi Juli dengan ambang yang ditulis April

Tabel ini adalah bentuk tertulis bagian 1.10, dikirim ke Dimas untuk ditandatangani sebelum Rabu 21 April. Baca dua kolom paling kanan: ambang "ubah" menunjuk masalah bentuk, ambang "hentikan" menunjuk masalah nilai. Semua angka dihitung per Kamis 2027-07-15.

| Indikator | Per 15 Apr | Lanjut bila | Ubah model bila | Hentikan bila |
|---|---|---|---|---|
| Detection atau laporan hunter baru aktif dari hunt sejak 1 April, ditambah detection lama yang diperbaiki karena purple | 0 (4 menunggu) | Minimal 4 baru aktif dan minimal 2 perbaikan | Usulan ada, tetapi kurang dari 4 aktif karena jalur macet | 0 baru dan 0 perbaikan |
| Hasil negatif teruji | 7/26 (26,9%) | Setiap hunt negatif sejak 20 April punya uji positif; minimal 8 hunt negatif lama diuji ulang di purple | | |
| Celah dan miskonfigurasi | Celah 19/22 berstatus, 3 ditutup + G03 sebagian; miskonfigurasi 4/20 diperbaiki | Celah berstatus minimal 90%, dan minimal 3 celah lagi ditutup atau keputusan anggaran Sysmon diambil (setuju atau tolak) | | 0 celah ditutup dan 0 keputusan anggaran |
| Hari terlindungi (hunt, purple, tinjauan) | Q1 100%, April 80% | Minimal 85% dari 20 April sampai 15 Juli | 60% sampai 85% | Di bawah 60% dua bulan berturut-turut tanpa keputusan pengganti |
| Umur usulan tanpa keputusan | 4 menunggu, 7-9 hari | Tidak ada yang lewat 10 hari kerja | Lebih dari 2 usulan lewat tenggat | |
| Beban L1 dari detection hunt | 3,0 per minggu | Rata-rata maksimal 3 per minggu, atau di atasnya dengan tuning yang sudah dijadwalkan | Di atas anggaran dua bulan tanpa tuning (detection baru dibekukan) | |
| Ketergantungan satu orang | 0 hunt dipimpin orang lain | Minimal 1 hunt dipimpin Yoga; Rudi menjalankan minimal 2 laporan hunter bulanan | 0 hunt dipimpin orang lain | |
| Kematangan | HMM2 terbukti, awal HMM3 | Minimal sepertiga hunt sejak 20 April adalah prosedur sendiri dengan uji positif | | |

Aturan keputusan: lanjut bila semua indikator "lanjut" terpenuhi, atau paling banyak dua tidak terpenuhi dengan alasan tertulis. Ubah model bila indikator hasil (baris 1 sampai 3) terpenuhi tetapi indikator proses (baris 4 sampai 7) jatuh di kolom "ubah". Hentikan atau bekukan bila indikator hasil jatuh di kolom "hentikan" walaupun waktunya terlindungi, atau bila hari terlindungi jatuh di kolom "hentikan". Insiden yang ditemukan, jumlah hunt, dan persentase heatmap dilaporkan sebagai konteks, tidak dihitung.

**Kapan gagal:** ambang diubah di bulan Juni "karena keadaan berubah" tanpa catatan dan tanpa persetujuan Dimas; atau baris kematangan dibiarkan menjadi klaim tanpa daftar hunt yang dihitung.

### 2.9 Satu halaman untuk Hendra dan jawaban untuk Dimas

Satu halaman ini dikirim lewat Dimas Kamis 2027-04-15 pukul 17:00, mengikuti urutan Day 15 bagian 1.8: keputusan yang diminta dulu, angka aktivitas paling bawah.

```
PROGRAM HUNT PT JAB: USULAN BENTUK PROGRAM, 15 APRIL - 28 JULI 2027
Untuk: Direktur Teknologi. Disusun SOC PT JAB. Angka per 15 April dapat ditelusuri ke
jab-hunt/docs/program-2027-Q2.md dan hunt-metrics-2027-Q1.md.

KEPUTUSAN YANG DIMINTA
1. Bentuk tim sampai Juli: tetap satu analyst L2 dua hari per minggu, dengan aturan bahwa hari
   hunting hanya diambil atas keputusan SOC lead dan dicatat, ditambah satu analyst L2 kedua
   (Yoga) ikut setengah hari enam kali dan memimpin satu hunt. Biaya: enam pagi piket L2 dua orang.
2. Peran threat hunter khusus: belum. Ditinjau lagi di evaluasi Juli bila anggaran Sysmon disetujui
   dan backlog yang siap dikerjakan melebihi kapasitas dua bulan berturut-turut.
3. Latihan purple team bulanan dengan Atomic Red Team: sesi pertama di lab (tanpa persetujuan baru);
   sesi berikutnya di dua komputer uji produksi bila disetujui (tiket change, akun uji, L1 diberi tahu).
4. Anggaran Sysmon untuk 229 workstation: masih menunggu keputusan; menjadi salah satu ukuran Juli.

APA YANG DIJALANKAN SAMPAI JULI
- 14 hunt terjadwal dari backlog yang dinilai ulang; identitas dan cloud lebih dulu (area insiden
  termahal 2026). Tiga sesi purple: menguji 12 detection hasil hunt dan membuktikan hasil "tidak
  ditemukan" lama. Hampir seperempat hari hunting dipakai untuk purple; itu disengaja.
- Usulan deteksi ke tim konten diputuskan paling lambat 10 hari kerja; tambahan alert untuk analyst
  L1 dibatasi rata-rata 3 per minggu (saat ini tepat 3).

KAPAN PROGRAM DINYATAKAN BERHASIL (ditetapkan sekarang, dihitung 15 Juli)
- Lanjut: minimal 4 deteksi atau laporan baru aktif dan 2 deteksi lama diperbaiki; setiap hasil
  "tidak ditemukan" baru dibuktikan dengan uji; celah telemetri bergerak (3 ditutup atau keputusan
  anggaran); hari hunting terlindungi minimal 85%; satu hunt dipimpin orang selain hunter utama.
- Ubah bentuk: hasil ada, tetapi waktu, jalur ke tim konten, atau beban L1 tidak terkendali.
- Hentikan: tidak ada perubahan yang dihasilkan walaupun waktunya tersedia.
- Bukan ukuran: jumlah hunt dan jumlah insiden yang kebetulan ditemukan.

KONTEKS: 29 hunt selesai sejak 1 Februari; 12 deteksi aktif; 1 kompromi ditemukan (Februari);
kematangan HMM2 terbukti dengan bukti awal HMM3.
```

Cara membaca halaman ini:

- **Keputusan dulu, bernomor.** Hendra bisa menjawab "1 dan 3 setuju, 4 nanti" tanpa membaca ulang seluruh halaman.
- **Harga ditulis.** Enam pagi piket dua orang dan seperempat hari hunting untuk purple disebut terang, supaya tidak muncul sebagai kejutan di bulan Juni.
- **Kriteria Juli ada di halaman yang sama dengan usulan.** Hendra menyetujui ukurannya sekarang, bukan menilai angka Juli dengan ukuran yang dibuat Juli.

Tabel berikut adalah jawaban untuk Dimas. Setiap baris merujuk subbagian di atas.

| Pertanyaan Dimas | Jawaban singkat | Dasar |
|---|---|---|
| Model tim dan dampaknya | A+ sampai Juli: tetap satu analyst dua hari, aturan perlindungan, Yoga sebagai pendamping enam pagi; piket Selasa/Kamis tetap tiga orang, enam pagi dua orang; peran khusus belum karena data | Bagian 1.1, 1.2 |
| Prasyarat | Data endpoint regional dan Sysmon (keputusan anggaran), sign-in service principal, lease DHCP POP, VM Linux lab, host uji produksi, orang kedua yang pernah memimpin hunt | Bagian 1.3 |
| Tingkat kematangan | HMM2 terbukti, awal HMM3; target Juli awal HMM3 yang terhitung, bukan HMM4 | Bagian 1.4 |
| Backlog dan kalender | Backlog dinilai ulang tiap Selasa dengan skor; 23 entri, 14 dijadwalkan (`-008`, `-033` sampai `-045`); kalender dikunci sampai 29 Juli dengan cadangan dan libur | Bagian 1.5, 1.6, 2.2, 2.4 |
| Purple team | Bulanan, 5 sampai 10 teknik; sesi 1 lab 6 Mei untuk 12 detection; sesi 2 uji positif hunt lama; sesi 3 regresi; produksi bila disetujui | Bagian 1.7, 2.5 |
| Jalur ke Sari | Satu antrean, satu format, review Rabu, tenggat 10 hari kerja, lima keputusan sah, anggaran L1 3 per minggu | Bagian 1.8, 2.6 |
| Metrik dan kriteria Juli | Tujuh metrik kesehatan; ambang lanjut, ubah, hentikan ditandatangani sebelum 21 April | Bagian 1.9, 1.10, 2.7, 2.8 |

**Kapan gagal:** satu halaman dibuka dengan "29 hunt dalam sepuluh minggu"; Hendra membaca kesibukan, bukan keputusan. Atau usulan dikirim tanpa harga piket, lalu Rudi pertama kali mendengar soal Kamis pagi dua orang dari jadwal yang sudah dikunci.

## 3. Lab praktik (di VM lab terisolasi)

**Prasyarat:** repo portofolio dari Day 16 (hunt `HUNT-CAP-001` sampai `-003` dan laporan lab pribadi), Splunk lab, VM Windows dengan Sysmon dan snapshot bersih, Atomic Red Team dan Invoke-AtomicRedTeam di VM lab, dan kalender pribadimu sendiri. Semua di lab pribadi; tidak ada data atau nama dari pekerjaan, dan PT JAB hanya contoh fiktif.

1. **Prasyarat jujur.** Buat tabel bagian 1.3 untuk lab-mu: data, alat, orang. Untuk setiap baris "Belum", tulis satu pekerjaan konkret dan kapan kamu akan mengerjakannya. Di lab satu orang, baris "orang" berisi kamu sendiri; tulis siapa yang bisa me-review laporanmu (rekan, mentor, komunitas).
2. **Posisi HMM.** Tempatkan lab-mu dengan tabel bagian 1.4 dan isi kolom bukti dari artefak di repo. Tulis satu tingkat kenaikan saja, dengan pekerjaan nyata dan bukti yang akan ditunjukkan.
3. **Backlog dengan skor.** Isi minimal delapan entri dengan templat YAML bagian 2.2, dari minimal empat sumber berbeda (intel publik, insiden publik yang kamu baca, celah dari hunt lab sebelumnya, keahlian domain). Hitung skor dengan rumus bagian 1.5, lalu tulis alasan bila urutanmu tidak mengikuti skor.
4. **Penilaian ulang terukur.** Ubah backlog menjadi CSV, unggah sebagai lookup di Splunk lab, dan jalankan query bagian 2.2 dengan tanggal acuan hari ini. Lakukan penilaian ulang sungguhan, ukur berapa menit yang dibutuhkan, dan putuskan apakah ritme mingguan realistis untukmu.
5. **Kalender kuartal pribadi.** Susun kalender 13 minggu dengan pola bagian 2.4: hari hunt yang realistis untuk jadwalmu, satu sesi purple per bulan, satu hari cadangan per bulan, dan satu tinjauan akhir. Tandai hari yang paling mungkin bertabrakan dengan pekerjaan atau keluarga, dan tulis aturan perlindunganmu sendiri.
6. **Purple sesi pribadi.** Pilih 5 test Atomic yang menghasilkan telemetri pola hunt lab-mu sebelumnya. Baca setiap test dengan `-ShowDetails`, jalankan `-CheckPrereqs` dan `-GetPrereqs` sebelum memutus VM dari internet, jalankan dengan `-ExecutionLogPath`, lalu `-Cleanup`. Unggah log eksekusi sebagai lookup dan jalankan query `map` bagian 2.5 setelah menyesuaikan format waktunya dengan satu baris log nyata.
7. **Lembar hasil.** Isi lembar hasil bagian 2.5 untuk kelima test, termasuk skor 0 sampai 5 dan kategori celah. Untuk setiap test tanpa alert, tulis apakah masalahnya visibilitas atau logika, dan masukkan sebagai entri backlog atau perbaikan rule.
8. **Pelacakan program.** Buat `jab_hunt_days.csv` versimu (`date`, `used_for`, `catatan`) dan isi dengan hari belajar empat minggu terakhir, termasuk hari yang tidak jadi dipakai. Jalankan query 1 bagian 2.7.
9. **Kriteria evaluasi pribadi.** Tulis tabel bagian 2.8 untuk portofoliomu sendiri, dengan ambang "lanjut, ubah, hentikan" untuk 90 hari ke depan, sebelum mulai mengerjakan. Simpan dengan tanggal hari ini di repo.

**Hasil yang sebaiknya tersimpan:**

- Tabel prasyarat lab dengan pekerjaan yang belum selesai.
- Posisi HMM lab dengan bukti dan rencana satu tingkat.
- Backlog minimal delapan entri berskor dari empat sumber, plus catatan waktu penilaian ulang.
- Kalender 13 minggu dengan aturan perlindungan pribadi.
- Log eksekusi Atomic (CSV), hasil query pencocokan telemetri, dan lembar hasil purple lima test dengan skor.
- Lookup hari belajar dan hasil query hari terlindungi.
- Tabel kriteria evaluasi bertanggal, ditulis sebelum periode dimulai.

**Variasi tantangan:** jalankan ulang lima test yang sama empat minggu kemudian tanpa mengubah apa pun, lalu hitung regresinya: berapa test yang dulu memicu dan kini tidak. Bila ada, cari penyebabnya (pembaruan Sysmon, perubahan konfigurasi, rule yang diedit) dan tulis sebagai laporan lessons learned satu halaman.

## 4. Troubleshooting

Tabel ini memuat masalah yang muncul saat program, bukan satu hunt, mulai berjalan. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Hari hunting sering hilang | Waktu hunting bukan blok yang dilindungi | Aturan pengambilan tertulis, catat di `jab_hunt_days.csv`, laporkan porsi hari terlindungi tiap bulan (bagian 2.7) |
| Backlog penuh tetapi tidak ada yang siap | Entri berupa judul tanpa Evidence; kesiapan tidak pernah diperbarui | Terapkan aturan mutu dan penilaian ulang Selasa (bagian 1.5) |
| Backlog hanya berisi turunan hunt sendiri | Tidak ada jalur masuk intel dan usulan L1 | Lihat `stats count BY sumber`; jadwalkan masukan intel bulanan (bagian 2.2) |
| Hunt menemukan hal yang sama berulang kali | Tidak ada jalur ke deteksi yang berfungsi | Ukur umur usulan dan status (query 2 bagian 2.7) |
| Usulan deteksi mengendap | Tanpa pemilik, tenggat, atau pilihan tunda dan tolak | Antrean tunggal, review Rabu, tenggat 10 hari kerja (bagian 1.8) |
| L1 mengeluh alert baru | Detection diaktifkan tanpa anggaran antrean | Hitung beban per minggu (query 3 bagian 2.7); tuning sebelum detection baru |
| Purple team selalu ditunda | Tidak ada tanggal terkunci dan pemilik bernama | Kunci tanggal satu kuartal di depan; sponsor Dimas (bagian 1.6) |
| Test Atomic tidak menghasilkan telemetri | Prasyarat tidak lengkap, timeout, atau Sysmon lab berbeda profil | `-CheckPrereqs`, naikkan `-TimeoutSeconds`, cocokkan profil Sysmon lab dengan produksi |
| Hasil purple tidak bisa dicocokkan dengan event | Waktu test hanya diingat; zona waktu tercampur | Pakai log eksekusi dengan kolom UTC dan rentang epoch (bagian 2.5) |
| Program berhenti saat hunter cuti | Ketergantungan satu orang | Hunter pendamping dan cadangan laporan terjadwal (bagian 1.2) |
| Evaluasi berubah jadi debat angka | Kriteria ditulis setelah angka keluar | Tanda tangani kriteria di awal periode (bagian 2.8) |
| Tim membicarakan otomasi dan model sementara hunt dasar belum teruji | Melompat tingkat HMM | Kembali ke telemetri dan uji positif hasil negatif (bagian 1.4) [S1] |

## 5. Kesalahan umum dan jebakan

- Menjanjikan program ke manajemen sebelum prasyarat data, alat, dan peran diperiksa, atau sebaliknya menunda program sampai semua celah tertutup.
- Mengukur hunter dengan jumlah tiket yang ditutup atau jumlah hunt per orang, sehingga hunting selalu kalah prioritas atau menjadi dangkal [S8].
- Memilih model tim tanpa menghitung harganya bagi piket dan on-call L2, lalu rekan mengetahui bebannya dari jadwal yang sudah jadi.
- Meminta peran threat hunter khusus untuk menyelesaikan masalah yang sebenarnya masalah data.
- Melompat tingkat HMM: membicarakan otomasi dan model sementara sebagian besar hasil negatif belum teruji.
- Membiarkan backlog tanpa penilaian ulang, sehingga entri lama tidak pernah ditutup dan entri baru hanya lahir dari hunt sendiri.
- Menyamakan purple team dengan hunt. Purple menguji apa yang sudah kita punya; hunt mencari apa yang luput.
- Menjalankan test Atomic di host produksi tanpa tiket change, akun uji, dan pemberitahuan ke L1, atau menjalankan test cloud tanpa otorisasi tertulis [S9][S11].
- Mencatat hasil purple tanpa GUID dan log eksekusi, sehingga regresi tidak bisa diukur di sesi berikutnya.
- Jalur ke deteksi tanpa pilihan tunda dan tolak, sehingga usulan mengendap tanpa keputusan.
- Mengaktifkan detection baru tanpa anggaran antrean L1, sehingga keberhasilan program dibayar shift malam.
- Menulis kriteria evaluasi setelah angka keluar, atau menjadikan jumlah insiden yang ditemukan sebagai syarat keberhasilan [S7].
- Mengambil angka ritme dari tulisan vendor sebagai target, bukan titik awal [S5].

## 6. Catatan terkini

Bagian ini menampung tanggal terbit, versi, dan perbedaan antar sumber. Berguna saat membuka dokumen sumbernya, tetapi tidak mengubah keputusan di atas.

- Panduan program SANS yang dipakai [S1] adalah blog Jan D'Herdt (instruktur LDR512 dan SEC566) bertanggal 20 Agustus 2026. Blog itu menyebut HMM sebagai "SANS Hunting Maturity Model"; model itu berasal dari David J. Bianco dan dipopulerkan Sqrrl lewat panduan "Hunt Evil" [S4] (Day 01 bagian 1.5). Rencana tiga fase di blog itu tidak memberi durasi per fase, sehingga pembagian minggu di bagian 2.3 adalah rancangan sendiri, dan blog itu meminta waktu sampai operasional dilacak tanpa menetapkan target.
- PTEF versi 4 dari SCYTHE menyebut dirinya perombakan untuk kemudahan praktisi; versi sebelumnya menambah penyedia pihak ketiga (v2) serta purple team yang dioperasionalkan dan berdedikasi (v3) [S9]. Halaman repo tidak mencantumkan tanggal rilis v4.
- Invoke-AtomicRedTeam versi terbaru di PowerShell Gallery adalah 2.3.0 (20 Maret 2025) [S11]. Repo Atomic Red Team menampilkan 1.878 atomics per akses 2026-10-18 [S10]; jumlah ini berubah seiring kontribusi.
- Survei SANS 2026 (rilis pers 23 September 2026): data 50% sebagai hambatan utama, staf 45%, in-house 58%, outsourcing 18% (2025: 30%), metodologi formal 37%, pengukuran hasil formal 40% (2024: 64%) [S15].
- Presentasi CTID tentang mematangkan adversary emulation (Crys Tan, 7 Maret 2025) membagi kematangan menjadi tiga tingkat, dengan "baby steps" untuk tim yang baru mulai [S13].
- Whitepaper TaHiTI yang dibaca (berkas di-host ulang Maret 2026) tidak memuat aturan bahwa ide baru masuk sebagai prioritas menengah atau rendah; isinya tentang backlog terbatas pada penyimpanan abstract, alat sederhana, dan pemilihan abstract paling relevan [S3]. Detail pengelolaan backlog lebih lanjut mungkin ada di dokumentasi lengkap atau alat MaGMa for threat hunting yang dirujuk whitepaper; cek di sana sebelum mengutipnya.

## 7. Cheat sheet

```
KENAPA MATI   hunting = pekerjaan pertama yang dikorbankan saat antrean naik (tak ada tenggat)
              penangkal: waktu terlindungi + backlog dinilai + jalur keluar bertenggat + kriteria di muka

MODEL TIM     eksternal (kurang konteks) | dedikasi (silo) | hibrida (tak sempat) | periodik (butuh rencana)
              hitung HARGA: piket eskalasi L2, on-call (1 dari 4 -> 1 dari 3 minggu bila satu L2 keluar)
              PT JAB sampai Juli: A+ = 1 analyst 2 hari + aturan perlindungan + pendamping + cadangan
              peran khusus baru bila data siap DAN backlog SIAP melebihi kapasitas 2 bulan

PRASYARAT     DATA (cakupan per host, retensi) | ALAT (yang dikuasai) | ORANG (siapa menyatakan insiden)
              celah = bagian rencana, bukan alasan menunda; jangan janji hasil di area tanpa data

HMM           0->1 data + indikator | 1->2 telemetri + prosedur terjadwal | 2->3 prosedur sendiri + uji positif
              3->4 otomasi; JANGAN melompat; level = bukti, bukan klaim

BACKLOG       masukan: intel | insiden | celah monitoring | hunt lain | usulan L1 | purple
              entri WAJIB: hipotesis + ABLE + kesiapan + di luar cakupan
              nilai ulang tiap Selasa; >30 hari perlu dinilai, >90 hari tutup/tulis ulang
              skor = relevansi(0-3) + celah(0-3) + kesiapan(0-2) + biaya(0/-1); nomor saat dijadwalkan

KALENDER      hunt Sel/Kam | backlog Selasa 30 mnt | review Sari Rabu | purple bulanan 5-10 TTP
              lessons learned < 2 minggu | cadangan 1/bulan | tinjauan kuartal | kunci 1 kuartal di depan
              hari diambil = keputusan Dimas + dicatat + diganti

PURPLE        full-knowledge; ukur telemetri -> alert -> triase; skor 0 (tak terlihat) .. 3 (alert) .. 5 (respons)
              celah: visibilitas | logika | diredam | proses | waktu
              Invoke-AtomicTest <T> -TestGuids <guid> -ShowDetails | -CheckPrereqs | -GetPrereqs
                 | -ExecutionLogPath <csv> -TimeoutSeconds <n> | -Cleanup
              lab dulu; produksi = tiket change + akun uji + L1 diberi tahu; cloud = otorisasi tertulis

KE DETEKSI    1 antrean (hunt-handover) | 1 format | review Rabu | tenggat 10 hari kerja
              keputusan: alert | risk | laporan hunter | tunda (syarat) | tolak (alasan)
              anggaran L1 rata-rata 3 alert/minggu; detection baru = tuning dulu bila penuh

KESEHATAN     hari terlindungi | porsi hunt | umur usulan | umur backlog + sumber | negatif teruji
              beban L1 | ketergantungan satu orang     (BUKAN hunt per hunter, query, laporan)

EVALUASI      kriteria ditulis SEBELUM angka: lanjut | ubah model (proses gagal) | hentikan (hasil nihil)
              bukan kriteria: jumlah hunt, insiden kebetulan, % hijau heatmap
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Kalau Pak Hendra menyetujui peran threat hunter penuh waktu, program PT JAB otomatis naik ke HMM3, karena hunter punya lima hari per minggu." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Level HMM ditentukan oleh bukti per kriteria, bukan oleh jumlah orang atau jam: HMM3 berarti membuat prosedur analisis sendiri, dan di PT JAB buktinya dihitung dari hunt dengan prosedur sendiri dan uji positif. Menambah waktu juga tidak menghapus hambatan utama PT JAB, yaitu data (229 workstation tanpa Sysmon), sehingga hunter penuh waktu sebagian besar akan menemukan celah yang sama. Peran khusus juga punya harga yang nyata: piket eskalasi setiap hari dibagi tiga orang dan on-call naik dari 1 dari 4 minggu menjadi 1 dari 3 minggu, plus risiko silo. Lihat bagian 1.2 dan 1.4.

</details>

**2. Skenario keputusan.** Selasa pagi, hari hunting, Yoga sakit dan antrean eskalasi L1 menumpuk. Tidak ada insiden. Apa yang paling tepat?

- A. Kamu langsung menggantikan piket dan tidak mencatat apa-apa, karena hanya satu hari.
- B. Dimas memutuskan apakah hari itu diambil; bila diambil, catat di `jab_hunt_days.csv` dengan `used_for=piket` dan siapa yang memutuskan, lalu pakai hari cadangan terdekat di kalender untuk hunt yang tertunda.
- C. Tetap hunting dan biarkan antrean menunggu, karena hari hunting adalah blok terlindungi.

<details><summary>Jawaban</summary>

B. Aturan perlindungan tidak berarti hari hunting tidak pernah diambil; artinya pengambilan diputuskan orang yang berwenang, tercatat, dan diganti bila bisa, sehingga pola pengambilan terlihat di metrik hari terlindungi. A keliru karena hari yang diambil tanpa catatan membuat porsi hari terlindungi selalu tampak 100% dan masalah model hibrida tidak pernah terlihat. C keliru karena antrean eskalasi yang menumpuk adalah risiko operasional nyata, dan aturan program menyerahkan keputusan itu ke Dimas, bukan ke hunter. Lihat bagian 1.2, 1.6, dan 2.7.

</details>

**3. Pertanyaan jebakan.** "Purple team dan hunt pada dasarnya sama, karena keduanya mencari jejak serangan di SIEM. Jadi kalender cukup diisi hunt; purple team bisa dihitung sebagai hunt." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Purple team adalah latihan full-knowledge: teknik dijalankan secara terbuka dan semua orang tahu apa yang dijalankan, sehingga tidak ada yang dicari; yang diukur adalah apakah telemetri muncul, detection memicu, dan triase berjalan. Hunt menjawab apakah ada yang luput dari detection, dengan pertanyaan terbuka dan hasil yang belum diketahui. Di PT JAB purple dipakai untuk menguji 12 detection hasil hunt dan memberi uji positif bagi hasil negatif lama, sehingga ia memperkuat hunt, bukan menggantikannya, dan dicatat sebagai hari purple, bukan hunt. Lihat bagian 1.6 dan 1.7.

</details>

**4. Skenario keputusan.** Usulan rule "JAB - Kredensial ditambahkan ke aplikasi atau service principal" dari `HUNT-2027-030` sudah menunggu sembilan hari. Sari sibuk, dan anggaran L1 sudah tepat 3 alert per minggu. Apa langkah yang tepat?

- A. Mengaktifkan rule sendiri di ES supaya tidak menunggu, karena volumenya hanya sekitar 1 per minggu.
- B. Membawa usulan ke review Rabu sebelum tenggat 10 hari kerja, dengan baris dampak antrean L1 yang menunjukkan bahwa keputusan "alert" butuh satu tuning, misalnya detection scheduled task AppData yang kini ikut melihat 63 workstation regional; bila Sari belum bisa, keputusannya ditulis sebagai tunda dengan syarat.
- C. Menunggu sampai Sari punya waktu, karena tenggat hanya panduan.

<details><summary>Jawaban</summary>

B. Jalur yang dibakukan punya antrean, review Rabu, tenggat, dan lima keputusan sah, dan baris dampak antrean L1 membuat biaya bagi L1 terlihat sebelum detection aktif; tunda dengan syarat adalah hasil yang tercatat, bukan kegagalan. A keliru karena role `jab_hunter` hanya ada di `jkt-splunk-sh01`, detection ES dipegang Sari di `jkt-splunk-es01`, dan reviewer harus orang lain selain pembuat usulan; mengaktifkannya juga melewati anggaran L1 tanpa keputusan. C keliru karena usulan tanpa batas waktu adalah pola yang membuat certutil menunggu 43 hari. Lihat bagian 1.8, 2.6, dan 2.7.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Gilang Ramadhan (analyst L1), dalam tiga kalimat, kenapa detection hasil hunt dibatasi anggaran rata-rata 3 alert per minggu dan apa artinya bagi shift-nya.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Setiap detection baru dari hunt menambah alert di antreanmu, jadi sebelum diaktifkan kami menghitung volumenya dari data nyata dan menjaga totalnya rata-rata maksimal 3 alert per minggu; empat minggu terakhir jumlahnya tepat 12. Kalau ada usulan baru yang akan membuat total lewat dari itu, detection lain dituning dulu atau diubah menjadi sinyal risk yang tidak langsung masuk antreanmu. Jadi kalau kamu melihat alert hasil hunt yang berulang jinak, catat di triase dan sampaikan ke Sari, karena itu bahan tuning yang kami pakai di review Rabu."

Kesalahan yang sering muncul:
- Menyebut anggaran sebagai batas jumlah detection, padahal yang dibatasi adalah alert per minggu.
- Tidak menyebut apa yang terjadi bila anggaran penuh (tuning atau sinyal risk), sehingga anggaran terdengar seperti alasan menolak usulan.
- Tidak memberi Gilang peran, padahal catatan triase L1 adalah sumber utama tuning.

</details>

**6. Pertanyaan jebakan.** "Di evaluasi Juli, program dinyatakan berhasil kalau menemukan minimal satu insiden lagi seperti INC-2027-040. Tanpa insiden, program gagal." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Insiden yang ditemukan saat hunt bergantung pada apakah penyerang kebetulan aktif di area dan rentang yang diperiksa, sehingga PEAK menyebutnya indikator lemah. Kriteria PT JAB ditulis di muka dan berbasis keluaran yang dikendalikan program: detection baru atau perbaikan detection, hasil negatif yang teruji, celah yang bergerak, serta indikator proses seperti hari terlindungi dan umur usulan. Insiden tetap dilaporkan sebagai konteks, tetapi tidak dijadikan syarat, karena syarat itu akan mendorong program menaikkan temuan jinak menjadi drama. Lihat bagian 1.10 dan 2.8.

</details>

**7. Interview question (English).** "Your SOC can only spare one analyst two days a week for threat hunting. How would you set up the program so it survives and can be judged fairly after six months?"

<details><summary>Sample answer</summary>

"I'd treat the time as the scarce resource and design around it. First, the two days are a protected block, like an on-call rota: only the SOC lead can take a hunting day, and every day taken is logged, so I can report what share of allocated days actually went to hunting. Second, I keep a scored backlog that I re-assess weekly, with each entry written as a testable hypothesis plus the data it needs and whether that data is ready, so I never start a week from scratch and I don't schedule hunts the data can't answer. Third, I agree an exit path with the detection engineering owner before I need it: one queue, a fixed handover template with volume and known false positives, a weekly review, a decision deadline of about ten working days, and explicit options to defer or reject. I also agree an alert budget for the L1 queue, so the program doesn't push its cost onto the night shift. Fourth, I schedule a small monthly purple team session with Atomic Red Team, logging test GUIDs and execution times, to prove that our detections fire and that our negative hunts weren't blind. Finally, I write the evaluation criteria at the start: what counts as continue, change the model, or stop, based on outcomes like new or improved detections, tested negatives and closed gaps, and process health like protected days and handover age. Number of hunts and lucky incident finds are context, not criteria. And I'd bring in a second analyst as a shadow hunter so the program doesn't depend on me alone."

What makes this answer strong: it addresses the real failure mode of hybrid teams (time being eaten by the queue), connects hunting to detection engineering with concrete service levels and an L1 budget, uses purple teaming to strengthen negative results, and commits to pre-agreed, outcome-based evaluation criteria instead of activity counts.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | SANS: From Alerts to Adversaries: A Pragmatic Guide to Launching (and Maturing) Your Threat Hunting Program (Jan D'Herdt) | https://www.sans.org/blog/from-alerts-to-adversaries-a-pragmatic-guide-to-launching-and-maturing-your-threat-hunting-program | sekunder (blog SANS) | 2026-08-20; dilihat 2026-10-09, dicek ulang 2026-10-18 | Sedang-tinggi. Empat model tim dan kelemahannya, prasyarat data/alat/orang, tiga fase tanpa durasi, dua jalur hunt awal, jangan melompat HMM dan perbaiki telemetri dulu, daftar metrik program, hunt dijadwalkan. Menyebut HMM sebagai "SANS HMM" |
| S2 | Splunk: Introducing the PEAK Threat Hunting Framework | https://www.splunk.com/en_us/blog/security/peak-threat-hunting-framework.html | sekunder (blog vendor, penulis kerangka) | 2023-04-18; dilihat 2026-10-09, dicek ulang 2026-10-18 | Tinggi untuk tiga tipe hunt (hypothesis-driven, baseline/EDA, M-ATH). Tidak membahas backlog atau prioritas |
| S3 | TaHiTI: a threat hunting methodology (whitepaper) | https://www.betaalvereniging.nl/wp-content/uploads/2026/03/TaHiTI-Threat-Hunting-Methodology-whitepaper.pdf | primer (pemilik metodologi) | di-host 2026-03; dirujuk 2026-10-09, dibaca ulang 2026-10-18 | Tinggi. Backlog abstract dengan alat sederhana, daftar trigger, handover ke IR/monitoring/intel/vulnerability management, daftar metrik (dwell time temuan, insiden, use case, intel, rekomendasi, kerentanan), penutup "pilih, prioritaskan, dokumentasikan masukan" |
| S4 | Sqrrl: Hunt Evil: Your Practical Guide to Threat Hunting (memuat HMM) | https://www.threathunting.net/files/hunt-evil-practical-guide-threat-hunting.pdf | primer (panduan yang memuat HMM) | dirujuk 2026-10-09 | Tinggi untuk definisi tingkat HMM; dokumen lama dengan konten pemasaran |
| S5 | Tulisan praktisi dan vendor tentang ritme program dan kalender purple team | (beberapa, lihat catatan sumber) | komunitas | dilihat 2026-10-09 | Rendah. Angka ritme dan tenggat tidak berasal dari standar atau survei yang bisa diverifikasi |
| S6 | MITRE ATT&CK Enterprise Matrix | https://attack.mitre.org/matrices/enterprise/ | primer | dilihat 2026-10-10 | Tinggi untuk katalog teknik yang dipakai sebagai dasar backlog, layer cakupan, dan pemilihan teknik purple team |
| S7 | Splunk: Measuring Hunting Success with PEAK (David Bianco) | https://www.splunk.com/en_us/blog/security/peak-threat-hunting-metrics.html | sekunder (blog vendor, penulis kerangka) | 2023-08-02; diakses 2026-10-18 | Tinggi. HMM minimal HMM2, banyak membidik HMM3, idealnya HMM4; jumlah hunt mengukur kerja keras; insiden saat hunt indikator lemah; lima metrik; detection ditautkan ke hunt asal; perbaikan detection lama dihitung |
| S8 | Intel 471: How threat hunting and good metrics help the business | https://www.intel471.com/blog/how-threat-hunting-and-good-metrics-help-the-business | sekunder (blog vendor) | 2026-02-10; diakses 2026-10-18 | Sedang. Hunt per hunter sebagai metrik yang merusak (burnout, keluarnya talenta), jumlah laporan sebagai pengalih, metrik baik termasuk sesi hunting per periode |
| S9 | SCYTHE: Purple Team Exercise Framework (PTEF) v4 | https://github.com/scythe-io/purple-team-exercise-framework ; https://github.com/scythe-io/purple-team-exercise-framework/blob/master/PTEFv4.md | sekunder (kerangka praktisi, lisensi MIT) | v4, tanggal rilis tidak tercantum; diakses 2026-10-18 | Sedang-tinggi. Definisi full-knowledge, peran, alur per TTP, tingkat deteksi, skor 0-5, kategori celah, laporan lessons learned kurang dari 2 minggu, ritme mingguan/bulanan 5-10 TTP/kuartalan/tahunan, anjuran produksi dengan uji di sistem serupa, otorisasi tertulis untuk cloud |
| S10 | Red Canary: Atomic Red Team | https://github.com/redcanaryco/atomic-red-team | primer (katalog test) | diakses 2026-10-18 | Tinggi. Pustaka test dipetakan ke ATT&CK, cepat, portabel, bisa diulang; lisensi MIT; 1.878 atomics per akses |
| S11 | Red Canary: Invoke-AtomicRedTeam wiki (Execute Atomic Tests (Local), Execution Logging) dan PowerShell Gallery | https://github.com/redcanaryco/invoke-atomicredteam/wiki ; https://github.com/redcanaryco/invoke-atomicredteam/wiki/Execute-Atomic-Tests-(Local) ; https://github.com/redcanaryco/invoke-atomicredteam/wiki/Execution-Logging ; https://www.powershellgallery.com/packages/Invoke-AtomicRedTeam | primer | 2.3.0 (2025-03-20); diakses 2026-10-18 | Tinggi. `-TestGuids`, `-GetPrereqs`, `-Cleanup`, `-TimeoutSeconds` (bawaan 120), log CSV bawaan dan kolomnya, `-ExecutionLogPath`, logger Attire/Syslog/WinEvent, peringatan izin dan mesin uji |
| S12 | MITRE CTID: Adversary Emulation Library | https://github.com/center-for-threat-informed-defense/adversary_emulation_library | primer | diakses 2026-10-18 | Tinggi. Full emulation plan dan micro emulation plan; micro plan tanpa red team; hanya dengan otorisasi eksplisit |
| S13 | MITRE CTID: Maturing Threat Informed Adversary Emulation with ATT&CK (Crys Tan) | https://ctid.mitre.org/events/apac-2025/14%20-%20Maturing%20Threat%20Informed%20Adversary%20Emulation%20with%20ATT&CK.pdf | sekunder (presentasi) | 2025-03-07; diakses 2026-10-18 | Sedang-tinggi. Tiga tingkat kematangan; "baby steps": pilih kelompok (opsional), pilih TTP, atomic testing, kerjakan detection/prevention; sumber Atomic Red Team dan micro emulation plan |
| S14 | MITRE ATT&CK: Adversary Emulation and Red Teaming | https://attack.mitre.org/resources/get-started/adversary-emulation-and-red-teaming | primer | diakses 2026-10-18 | Tinggi. ATT&CK sebagai bahasa bersama red team; rujukan presentasi purple teaming, CALDERA, emulation plan |
| S15 | SANS: rilis pers SANS 2026 Threat Hunting Survey | https://www.sans.org/press/announcements/threat-hunters-call-data-their-biggest-barrier-overtaking-staffing-first-time-survey-finds | sekunder (rilis pers penyelenggara survei) | 2026-09-23; diakses 2026-10-18 | Sedang-tinggi. Data 50%, staf 45%, in-house 58%, outsourcing 18% (2025: 30%), metodologi formal 37%, pengukuran formal 40% (2024: 64%); kaitan pengukuran dengan anggaran |
| S16 | Threat-Hunting Day 01-18 (laporan hunt, register, metrik Q1, evaluasi Q1, usulan April) | (lokal) | rujukan internal | 2026-10-18 | Sumber semua angka PT JAB di bagian 2.1 dan seterusnya |

**Catatan sumber:** angka ritme dan tenggat yang tidak bersumber kerangka (hunt mingguan, 8 sampai 15 teknik per latihan, lessons learned lima hari kerja, tenggat keputusan sepuluh hari kerja, dua hunt terstruktur per bulan) berasal dari tulisan praktisi dan vendor [S5], bukan standar atau survei, sehingga ditandai sebagai titik awal di teks; angka PTEF (5 sampai 10 TTP per latihan bulanan, laporan kurang dari 2 minggu) berasal dari kerangka praktisi yang bisa dirujuk [S9] tetapi juga bukan standar. Satu tulisan purple team mengutip survei SANS 2024 dengan klaim perbaikan deteksi 22 poin dalam 12 bulan; klaim itu belum bisa dicocokkan dengan laporan survei aslinya, jadi tidak dipakai. Label skor PTEF untuk nilai 1, 2, dan 4 tidak terbaca di bagian dokumen yang diperiksa. Format waktu kolom log eksekusi Invoke-AtomicRedTeam tidak dicontohkan di halaman yang diperiksa [S11], sehingga format `strptime` di bagian 2.5 harus dicocokkan dengan satu baris log nyata. Nama index penyimpan finding di ES 8.x tidak disebut dokumentasi findings ES 8.7 (Day 15). Skema lookup program (`jab_hunt_days.csv`, `jab_hunt_handover.csv`, `jab_hunt_backlog.csv`), rumus skor backlog, ambang 30/90 hari, anggaran L1, dan seluruh angka, nama, host uji, tanggal, kalender, dan kriteria PT JAB adalah penerapan catatan ini pada organisasi fiktif, bukan hasil eksekusi nyata.
