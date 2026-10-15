---
day: 02
title: 'IR plan, RACI, matriks eskalasi, on-call, dan handover shift'
researched_on: 2026-10-14
versions_checked: 'NIST SP 800-61 Rev. 3 (April 2025, CSF 2.0 Community Profile); NIST SP 800-61 Rev. 2 (Agustus 2012, digantikan Rev. 3); NCSC UK Incident management collection (dicek 2026-10-14); Google SRE Book bab 14 Managing Incidents (2017); PagerDuty Incident Response Documentation (dicek 2026-10-14); CISA Federal Government Cybersecurity Incident and Vulnerability Response Playbooks (halaman dicek 2026-10-14)'
---

# Day 02: IR plan dan perangkatnya (RACI, matriks eskalasi, on-call, dan handover shift)

Cakupan: susunan dokumen IR dari kebijakan sampai playbook, isi IR plan menurut NIST SP 800-61 r2 dan r3 serta NCSC UK, pembagian kepemilikan dengan RACI, pemicu dan batas waktu eskalasi, kesiapan on-call, serta handover shift dan serah terima peran IC saat insiden masih berjalan.

## Ide inti

Saat insiden berjalan, tidak ada waktu untuk memutuskan siapa yang berwenang, siapa yang harus dihubungi, dan lewat kanal apa. Semua itu harus diputuskan sebelumnya dan ditulis. IR plan memberi wewenang, RACI memberi kepemilikan per tindakan, matriks eskalasi memberi pemicu dan batas waktu, jadwal on-call memberi orang yang siap dengan akses yang sudah disiapkan, dan handover menjaga konteks tidak hilang saat shift berganti. Bila salah satunya kosong, insiden tidak macet karena kurang kemampuan teknis, tetapi karena orang menunggu izin, menunggu jawaban, atau mengulang pekerjaan.

Kamu sudah mengenal pola ini dari NOC. Saat gangguan massal jam dua pagi, engineer piket tahu siapa yang ditelepon dan setelah berapa menit pindah ke nomor berikutnya, punya akses ke perangkat, tahu bahwa blackhole route saat DDoS boleh dipasang tanpa menunggu rapat change, dan shift pagi menerima daftar gangguan terbuka. IR plan adalah prosedur gangguan major yang sama, dengan dua perbedaan: wewenangnya menyentuh hal hukum dan bisnis (data pribadi, regulator, pernyataan publik), dan pemicu eskalasinya bukan hanya jumlah pelanggan terdampak, tetapi juga jenis data dan jenis akun yang disalahgunakan.

```
Kebijakan IR            siapa berwenang, definisi insiden        (disetujui direksi)
  IR plan JAB-IRP-01    peran, severity, eskalasi, kanal, lapor  (disetujui Direktur Teknologi)
    RACI                siapa mengerjakan, siapa memutuskan      (per tindakan)
    Matriks eskalasi    pemicu -> siapa -> lewat apa -> batas waktu -> berikutnya
    Jadwal on-call      siapa siap malam ini, dengan akses apa
    Playbook JAB-PB-NN  langkah per jenis insiden
  Handover              konteks pindah antar shift dan antar IC tanpa hilang
```

Situasi yang dipakai sepanjang Day ini: PT Jaringan Anak Bangsa (PT JAB) adalah ISP menengah fiktif dengan sekitar 1.200 karyawan, NOC 24/7 di Jakarta, dan data pribadi pelanggan di sistem billing dan portal pelanggan. PT JAB tidak punya tim IR khusus; insiden ditangani CSIRT virtual yang ditarik dari pekerjaan harian masing-masing. Selasa 22 September 2026, post-incident review untuk `INC-2026-012` (SEV-2, web shell di server portal pelanggan `jkt-portal01`, Sabtu 12 September 2026 dini hari) menghasilkan ringkasan timeline berikut:

> - 01:40 alert `SOC-2026-0127`: file PHP baru di direktori upload `jkt-portal01`, lalu request POST ke file itu dari `198.51.100.23`.
> - 01:52 analyst L1 shift malam mengonfirmasi indikasi web shell. Ia tidak tahu siapa yang harus ditelepon; `JAB-IRP-01` versi 1.2 hanya menulis "laporkan ke Tim Keamanan via email". Ia mengirim email ke SOC lead dan menunggu.
> - 02:42 L1 menemukan nomor Dimas Prasetyo (SOC lead) di grup chat lama dan menelepon. Waktu terbuang 50 menit.
> - 02:55 Dimas memvalidasi sendiri (malam itu tidak ada L2 on-call), menyatakan insiden SEV-2, dan meminta NOC memblokir `198.51.100.23` di firewall perimeter.
> - 03:05 shift lead NOC menolak: perubahan firewall perimeter wajib disetujui Manajer NOC lewat change darurat, dan tidak ada dokumen yang memberi SOC wewenang memerintah NOC.
> - 04:20 Manajer NOC Bambang Hartono baru bisa dihubungi. Blokir terpasang 04:31, 96 menit setelah diminta. Selama itu web shell menerima 7 request POST lagi.
> - 07:00 handover shift malam (pukul 23:00 sampai 07:00) ke shift pagi berisi satu baris: "INC-2026-012 portal masih investigasi."
> - 07:15 sampai 09:30 shift pagi mengulang analisis yang sudah selesai malam sebelumnya dan meminta NOC memblokir IP yang sudah diblokir.

Di akhir rapat, Direktur Teknologi Hendra Wijaya menulis di kanal insiden:

> "Revisi JAB-IRP-01. Saya mau jawaban tertulis untuk: (1) siapa yang boleh menyatakan insiden dan memerintahkan blokir malam itu, tanpa menunggu saya atau Pak Bambang; (2) untuk setiap tindakan penting, siapa yang mengerjakan dan siapa yang memutuskan; (3) kapan L1 wajib menelepon, siapa, lewat apa, dan apa yang dilakukan kalau tidak diangkat; (4) siapa yang seharusnya siap malam itu, dan dengan akses apa; (5) apa yang wajib ada di handover supaya shift pagi tidak mengulang; (6) bagaimana kita tahu versi baru ini tidak gagal dengan cara yang sama."

Pertanyaan 1 dijawab bagian 1.1 dan 1.2, pertanyaan 2 bagian 1.3, pertanyaan 3 bagian 1.4, pertanyaan 4 bagian 1.5, pertanyaan 5 bagian 1.6, dan pertanyaan 6 bagian 1.7. Jawaban lengkapnya dalam bentuk dokumen ada di bagian 2.

**Kapan relevan:** saat menyusun atau merevisi IR plan, setelah post-incident review menemukan keterlambatan karena wewenang atau kontak, saat auditor meminta IR plan dan bukti pengujiannya, dan saat kamu mulai masuk jadwal on-call atau memimpin insiden sebagai IC.
**Kapan bukan jawaban:** dokumen ini tidak menggantikan kemampuan teknis atau playbook per jenis insiden. Plan yang rapi tidak menolong bila orang on-call tidak bisa login ke EDR, dan plan yang tidak pernah diuji sering gagal di titik yang sama dengan insiden terakhir.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Peran saat insiden dan skala severity sudah dibahas di Day 01 dan tidak diulang di tabel ini. Ringkasnya: incident commander (IC) memimpin dan memutuskan arah penanganan, executive sponsor (di PT JAB: Direktur Teknologi) memutuskan hal yang berdampak bisnis, technical lead memimpin analisis, dan scribe mencatat timeline beserta keputusan. Tabel berikut memuat istilah baru Day ini; kolom padanan memakai analogi NOC dan SOC yang sama di semua Day IR.

| Istilah | Arti singkat | Padanan di NOC/SOC |
|---|---|---|
| Kebijakan IR (IR policy) | Pernyataan manajemen bahwa insiden wajib ditangani, berisi definisi, peran, dan wewenang; jarang berubah | Kebijakan operasi jaringan yang ditandatangani direksi |
| IR plan | Dokumen yang menjalankan kebijakan: peran, severity, eskalasi, kanal komunikasi, kewajiban lapor, pengujian | Prosedur penanganan gangguan major dan BCP NOC |
| Prosedur dan playbook | Langkah kerja per jenis insiden atau per tugas teknis | Runbook gangguan per jenis (fiber putus, BGP flap) |
| Wewenang di muka (pre-authorization) | Izin tertulis untuk tindakan tertentu tanpa menunggu persetujuan rutin, dengan syarat yang jelas | Izin tetap memasang blackhole route saat DDoS tanpa menunggu rapat change |
| RACI | Pembagian peran per aktivitas: Responsible, Accountable, Consulted, Informed | Matriks eskalasi NOC: siapa mengerjakan, siapa menyetujui |
| Matriks eskalasi | Tabel pemicu, kontak, kanal, batas waktu, dan kontak berikutnya bila tidak dijawab | Eskalasi tiket NOC dari L1 ke engineer ke vendor |
| Escalation dan elevation | Menambah sumber daya atau mempercepat penanganan (escalation) vs melibatkan manajemen yang lebih tinggi (elevation) | Menambah engineer ke gangguan vs melapor ke GM saat gangguan massal |
| Timeout eskalasi | Batas menunggu jawaban sebelum pindah ke kontak berikutnya | Aturan piket NOC: tidak diangkat dalam N menit, telepon engineer berikutnya |
| On-call (primary, secondary) | Orang yang terjadwal siap dipanggil di luar jam kerja, dengan cadangan | Jadwal piket engineer NOC |
| Akun break-glass | Akun darurat berhak tinggi yang disimpan tersegel, hanya dipakai bila jalur akses normal tidak tersedia, dan setiap pemakaiannya ditinjau | Akun lokal console router saat server TACACS atau RADIUS tidak bisa diakses |
| Handover shift | Serah terima pekerjaan yang sedang berjalan ke shift berikutnya | Serah terima shift NOC dengan daftar gangguan terbuka |
| Serah terima peran IC | Pemindahan komando insiden secara eksplisit dari satu IC ke IC berikutnya | Incident manager NOC menyerahkan pimpinan bridge ke penggantinya |
| Kanal out-of-band (OOB) | Jalur komunikasi di luar email dan chat korporat, disiapkan sebelum insiden | Jalur manajemen out-of-band (console server) saat jaringan produksi bermasalah |
| IR retainer | Kontrak dengan penyedia DFIR yang siap dipanggil dengan SLA respons | Kontrak support vendor dengan SLA respons |
| Tabletop exercise | Latihan diskusi skenario untuk menguji keputusan dan komunikasi | Drill gangguan di NOC tanpa menyentuh perangkat |

### 1.1 Tiga lapis dokumen: kebijakan, plan, dan playbook

Shift lead NOC malam itu tidak salah membaca aturan. Prosedur change management PT JAB memang mewajibkan persetujuan Manajer NOC untuk firewall perimeter, dan tidak ada dokumen di atasnya yang membuat pengecualian untuk insiden. Masalahnya ada di susunan dokumen: wewenang SOC tidak pernah ditulis di lapisan yang bisa mengalahkan prosedur operasional.

NIST SP 800-61 r2 membedakan tiga jenis dokumen: kebijakan, plan, dan prosedur. Prosedur harus berdasar pada kebijakan dan plan [S2]. Revisi 3 mempertahankan urutan yang sama dan menambahkan bahwa banyak organisasi menulis prosedurnya dalam bentuk playbook, yaitu langkah yang bisa langsung dikerjakan untuk skenario tertentu [S1]. Untuk contoh playbook, NIST r3 merujuk playbook CISA yang disusun sebagai prosedur operasional standar bagi instansi sipil federal Amerika Serikat atas mandat Executive Order 14028 [S1][S10].

Tabel berikut membantu menentukan sebuah aturan harus ditulis di lapisan mana. Kolom "Siapa menyetujui" yang paling menentukan: aturan hanya bisa mengalahkan prosedur lain bila disetujui orang yang berwenang atas keduanya.

| Lapisan | Pertanyaan yang dijawab | Siapa menyetujui di PT JAB | Seberapa sering berubah | Contoh PT JAB |
|---|---|---|---|---|
| Kebijakan IR | Apakah insiden wajib ditangani, apa definisinya, siapa berwenang? | Direksi | Jarang, ditinjau tahunan | Bab penanganan insiden di Kebijakan Keamanan Informasi PT JAB |
| IR plan | Bagaimana kemampuan IR diorganisasi: peran, severity, eskalasi, kanal, kewajiban lapor, pengujian? | Direktur Teknologi | Tahunan dan setelah insiden besar | `JAB-IRP-01` versi 2.0 |
| Playbook dan prosedur | Langkah apa untuk jenis insiden atau tugas ini? | SOC lead | Sering, setiap ada pelajaran baru | `JAB-PB-01` Ransomware sampai `JAB-PB-04` Kompromi aplikasi web |
| Lampiran operasional | Siapa ditelepon malam ini, di nomor berapa? | SOC lead | Mingguan | Jadwal on-call, daftar kontak |

Dua hal yang sering tertukar. Pertama, playbook menjawab "bagaimana", bukan "siapa boleh". Playbook `JAB-PB-04` boleh menulis "blokir IP penyerang di firewall perimeter", tetapi tanpa wewenang di plan, NOC tetap berhak menolak seperti malam itu. Kedua, lampiran operasional dipisah dari badan plan karena berubah tiap minggu; plan yang harus disetujui ulang direktur setiap kali nomor telepon berubah akan cepat usang.

### 1.2 Isi IR plan: wewenang lebih dulu daripada langkah teknis

Pertanyaan pertama Hendra ("siapa yang boleh memerintahkan blokir tanpa menunggu saya atau Pak Bambang") adalah pertanyaan wewenang. `JAB-IRP-01` versi 1.2 penuh langkah teknis, tetapi tidak menjawab pertanyaan itu, sehingga malam itu semua orang bertindak benar menurut aturannya masing-masing dan insiden tetap tertunda 96 menit.

Sumber primer memberi daftar isi yang mirip, dengan penekanan berbeda. NIST r2 memisahkan elemen kebijakan (komitmen manajemen, tujuan, scope, definisi, peran dan tingkat wewenang, severity, ukuran kinerja, formulir pelaporan) dari elemen plan (misi, strategi dan sasaran, persetujuan manajemen senior, pendekatan organisasi, cara tim berkomunikasi ke dalam dan ke luar, metrik, roadmap pematangan, dan posisi program di organisasi) [S2]. Elemen peran di r2 secara eksplisit menyebut wewenang tim untuk menyita atau memutus perangkat, kewajiban melapor jenis insiden tertentu, aturan berbagi informasi ke luar, serta titik handoff dan eskalasi [S2]. NIST r3 menulis ulang daftar elemen kebijakan dengan isi serupa, termasuk peran mana yang berwenang menyita, memutus, atau mematikan aset teknologi [S1]. NCSC UK menulis dari sudut yang lebih praktis: daftar kontak kunci, kriteria eskalasi, alur proses, nomor conference call yang selalu tersedia, dan panduan kapan melibatkan Legal atau HR [S3].

Tabel berikut menggabungkan ketiganya. Gunakan kolom terakhir untuk mengecek apakah sebuah IR plan sudah lengkap; kolom tengah berguna saat auditor atau interviewer bertanya "menurut NIST, isi IR plan apa saja?".

| Elemen | NIST r2 (2012) | NIST r3 (2025) dan kategori CSF 2.0 | NCSC UK | Ada di butir `JAB-IRP-01` v2.0 |
|---|---|---|---|---|
| Komitmen dan persetujuan manajemen | Elemen kebijakan dan plan | Elemen kebijakan; ID.IM-04 meminta plan menyebut sumber daya dan dukungan manajemen | - | Halaman persetujuan |
| Tujuan, scope, definisi | Elemen kebijakan | Elemen kebijakan, termasuk definisi event, insiden, dan investigasi | - | 1 dan 3 |
| Peran, tanggung jawab, wewenang | Elemen kebijakan, termasuk menyita atau memutus perangkat | Elemen kebijakan; GV.RR-02: peran IR didokumentasikan dan setiap pihak diberi wewenang yang dibutuhkan | Wewenang yang didelegasikan, deputi bila kontak utama tidak ada, wewenang di muka untuk tim teknis | 2 dan 4 |
| Severity dan prioritas | Elemen kebijakan | Elemen kebijakan; RS.MA-03: insiden dikategorikan dan diprioritaskan | Matriks severity menentukan eskalasi | 3 |
| Eskalasi dan handoff | Titik handoff dan eskalasi | RS.MA-04: insiden di-escalate atau di-elevate sesuai kebutuhan | Ambang eskalasi, kontak di luar jam kerja, seberapa cepat eskalasi harus terjadi | 5 |
| Komunikasi internal dan eksternal | Cara tim berkomunikasi | RS.CO-02: prosedur menetapkan apa dilaporkan ke siapa dan kapan; RS.CO-03: update rutin ke pimpinan | Minimal 2 orang dan 2 metode kontak per fungsi; kanal alternatif bila email atau telepon tidak bisa dipakai | 6 |
| Kewajiban hukum dan pelaporan | Persyaratan melapor jenis insiden tertentu | GV.OC-03: persyaratan hukum mencakup notifikasi dan pelaporan kebocoran | Definisikan insiden yang wajib dilaporkan; siapkan formulir | 7 |
| Playbook dan prosedur | SOP berdasar kebijakan dan plan | Playbook sebagai bentuk prosedur | Mulai dari 3 sampai 5 jenis insiden paling mungkin dan paling berisiko | 8 |
| Metrik, pengujian, review | Metrik, roadmap; plan direview minimal tahunan | ID.IM-01 sampai ID.IM-04: perbaikan dari evaluasi, latihan, dan insiden; plan direview berkala | Latihan untuk skenario yang menyangkut kewajiban hukum | 9 |
| Hubungan dengan rencana lain | Posisi program di organisasi | ID.IM-04: plan IR diselaraskan dengan business continuity plan (BCP); RS.MA-01: rencana lain seperti BCP dan disaster recovery plan (DRP) dijalankan bila perlu | Plan terhubung ke rencana business continuity, disaster recovery, dan komunikasi | 9 dan 10 |

Sumber tabel: [S1] untuk kolom r3, [S2] untuk kolom r2, [S3] untuk kolom NCSC.

Dua gagasan dari tabel ini yang langsung menjawab masalah malam itu:

1. **Wewenang harus spesifik per tindakan.** Kalimat "Tim Keamanan menangani insiden" tidak memberi siapa pun hak memerintah NOC. NIST menyebut wewenang memutus atau mematikan aset sebagai bagian peran [S1][S2], dan NCSC menyarankan mempertimbangkan wewenang di muka bagi tim teknis untuk bertindak mandiri pada situasi berisiko tinggi ketika containment cepat kemungkinan besar mengurangi dampak [S3]. Untuk PT JAB, artinya plan menulis: IC on-call boleh memerintahkan blokir IOC terkonfirmasi di firewall perimeter, dan NOC menjalankannya sebagai change darurat yang dicatat dan ditinjau setelahnya.
2. **Wewenang besar tetap di atas.** NIST r3 menyebut pimpinan organisasi bisa memegang keputusan untuk tindakan berdampak tinggi seperti mematikan atau membangun ulang layanan kritis [S1]. Di PT JAB, mematikan portal pelanggan, RADIUS, atau billing tetap keputusan executive sponsor. Wewenang di muka tidak berarti IC boleh melakukan apa saja; artinya batasnya sudah ditulis sebelum malam insiden.

NIST r3 juga menyebut bahwa pihak ketiga yang ikut menangani insiden (penyedia SOC terkelola atau MSSP, penyedia cloud, retainer) harus punya pembagian tanggung jawab yang jelas di kontrak, termasuk wewenang bertindak atas nama organisasi dan batasannya [S1]. NIST r2 mencatat organisasi sering enggan memberi pihak luar wewenang keputusan operasional seperti memutus web server, sehingga titik keputusan itu perlu ditulis [S2]. Untuk PT JAB: retainer PT Forensik Digital Contoh memberi rekomendasi dan mengambil bukti, tetapi keputusan containment tetap di IC.

### 1.3 RACI: satu tindakan, satu pemilik keputusan

Penolakan NOC malam itu bisa dibaca sebagai dua orang yang sama-sama merasa memiliki keputusan blokir: Dimas sebagai IC dan Bambang sebagai pemilik firewall. Bila dua orang sama-sama merasa memutuskan, saat salah satunya tidak bisa dihubungi, keputusan berhenti.

RACI memetakan setiap aktivitas ke empat peran. Tabel berikut adalah definisi kerja yang dipakai di catatan ini; perhatikan kolom "Jumlah per aktivitas", karena di situlah aturan terpentingnya.

| Huruf | Peran | Arti kerja | Jumlah per aktivitas |
|---|---|---|---|
| R | Responsible | Mengerjakan tindakan atau menyiapkan keputusannya | Minimal satu, boleh lebih |
| A | Accountable | Pemilik hasil: menyetujui, menandatangani, dan menjawab bila ditanya pimpinan | Tepat satu |
| C | Consulted | Dimintai pendapat sebelum tindakan atau keputusan; komunikasi dua arah | Boleh beberapa |
| I | Informed | Diberi tahu setelah keputusan atau tindakan; komunikasi satu arah | Boleh beberapa |

Definisi dan aturannya mengikuti panduan RACI umum [S9]:

- **Satu Accountable per aktivitas.** Dua A berarti tidak ada pemilik, dan keputusan melambat. Ini persis yang terjadi pada blokir firewall malam itu.
- **Setiap aktivitas punya minimal satu R.** Aktivitas dengan A tetapi tanpa R hanya menjadi harapan.
- **Satu orang boleh R dan A sekaligus.** Contohnya IC yang mengaktifkan retainer dalam kuota kontrak: ia yang menilai kebutuhan dan ia pula yang memutuskan. Ditulis "A/R". Untuk declare, PT JAB sengaja memisahkan keduanya: L2 on-call memvalidasi dan mengusulkan (R), IC menyatakan (A).
- **Jangan isi semua sel.** Terlalu banyak C memperlambat keputusan; terlalu banyak I membuat kanal insiden bising.

Jebakan yang paling sering di IR adalah R dan A tertukar. Pemilik sistem (Manajer NOC untuk firewall, tim Infrastruktur untuk AD) biasanya Responsible untuk mengeksekusi, bukan Accountable atas keputusan containment. Bila pemilik sistem ditulis sebagai A, IC harus meminta izin setiap kali, dan pemilik sistem bisa menunda dengan alasan operasional. Kebalikannya juga salah: bila IC ditulis sebagai A untuk mematikan portal pelanggan, IC memikul keputusan bisnis yang menyangkut 400 ribu pelanggan dan kontrak korporat, yang menurut NIST dan peran PT JAB sendiri berada di tangan pimpinan [S1].

Cara mengecek RACI yang sudah jadi: baca per baris (tepat satu A, minimal satu R), lalu per kolom. Kolom yang penuh A menandakan orang itu menjadi titik macet; kolom yang kosong menandakan orang itu tidak perlu ada di matriks. RACI lengkap PT JAB ada di bagian 2.2.

### 1.4 Matriks eskalasi: pemicu, kontak, kanal, dan batas waktu

L1 shift malam sebenarnya sudah menilai dengan benar pukul 01:52: ada web shell di server pelanggan. Yang tidak ia punya adalah aturan "kondisi ini berarti telepon orang ini sekarang, dan bila tidak diangkat dalam N menit, telepon orang berikutnya". Tanpa aturan itu, ia memilih kanal paling sopan (email) dan menunggu.

NIST r3 memakai dua istilah yang berguna untuk membaca matriks: escalation umumnya berarti menambah sumber daya atau mempercepat kerangka waktu, sedangkan elevation berarti melibatkan tingkat manajemen yang lebih tinggi [S1]. Matriks yang baik mengatur keduanya: kapan L2 dan IC ditarik masuk (escalation), dan kapan Direktur Teknologi, Legal, atau DPO harus tahu (elevation). NIST r3 juga menyarankan agar keputusan triage, prioritas, escalation, dan elevation berdasar pada faktor evaluasi risiko yang sudah ditetapkan, misalnya kritikalitas aset, dampak fungsional, dampak pada data, tahap aktivitas penyerang, dan kemampuan pulih [S1].

Pemicu eskalasi keamanan berbeda dengan pemicu di NOC. Di NOC, pemicunya biasanya durasi gangguan atau jumlah pelanggan terdampak. Di IR, beberapa pemicu tidak terkait layanan sama sekali:

- **Severity:** kandidat SEV-2 atau SEV-1 berarti IC harus aktif dalam batas waktu tertentu; L2 tidak menanganinya sendirian sampai pagi.
- **Jenis data:** data pribadi pelanggan mungkin terdampak, walau layanan berjalan normal. Ini memicu elevation ke pejabat pelindungan data pribadi (DPO, di PT JAB Agus Setiawan) dan Legal, karena bisa memunculkan kewajiban pelaporan menurut UU Pelindungan Data Pribadi (UU PDP).
- **Jenis akun:** akun privileged (`adm.*`, domain admin, service account seperti `svc_billing`) disalahgunakan.
- **Sistem kritis ISP:** `jkt-radius01`, `jkt-billing01`, dan DNS resolver. Kompromi di sini bisa menjadi gangguan layanan massal.
- **Pihak luar:** media atau pelanggan korporat sudah bertanya. Insiden yang sudah diketahui pihak luar butuh Corporate Communication dan executive sponsor, apa pun severity teknisnya.

Target waktu tiap severity sudah ditetapkan di Day 01. Tabel berikut mengulangnya karena matriks eskalasi harus memenuhi target ini; cari kolom "Target waktu" saat menghitung timeout.

| Severity | Ringkasan kriteria | Target waktu |
|---|---|---|
| SEV-1 | Layanan pelanggan terganggu luas, kebocoran data pribadi besar, ransomware menyebar, domain admin dikuasai | IC aktif maks 15 menit, executive sponsor diberi tahu maks 30 menit, update setiap 1 jam |
| SEV-2 | Kompromi terkonfirmasi tetapi terbatas, data pribadi mungkin terdampak terbatas, akun berhak tinggi disalahgunakan | IC aktif maks 30 menit, update setiap 4 jam |
| SEV-3 | Satu endpoint atau akun biasa tanpa tanda penyebaran | Ditangani L2 pada jam kerja, update harian |
| SEV-4 | Aktivitas mencurigakan tanpa dampak | Antrean SOC biasa |

Batas waktu menunggu jawaban (timeout) harus dihitung mundur dari target ini. PagerDuty menyarankan timeout eskalasi 5 menit untuk tim engineering-nya, dengan level ketiga adalah seluruh tim [S6]. Alurnya mengikuti aturan declare PT JAB: L1 menelepon L2 on-call, L2 memvalidasi dan mengusulkan, lalu L2 menelepon IC yang menyatakan insiden. PT JAB memakai timeout 5 menit untuk L2 dan 10 menit untuk IC pada SEV-2, karena anggota CSIRT virtual di rumah perlu waktu bangun dan membuka laptop. Hitungannya untuk SEV-2: L1 menelepon L2 primary pada menit 0; bila tidak diangkat, L1 menelepon IC langsung pada menit 5; backup IC pada menit 15; Direktur Teknologi pada menit 25 untuk menunjuk IC. Skenario terburuk masih memberi IC aktif di menit 30. Untuk pemicu SEV-1 targetnya 15 menit, jadi L1 menelepon L2 dan IC bersamaan, backup IC pada menit 5, dan Direktur Teknologi pada menit 10. Malam 12 September, dengan aturan ini, IC sudah aktif paling lambat 02:22, bukan 02:55.

Kanal juga bagian dari matriks. Paging di luar jam kerja memakai telepon, bukan email atau chat, karena email tidak membangunkan orang. Setelah insiden dinyatakan, koordinasi pindah ke kanal `#inc-2026-NNN`. Bila ada dugaan email atau chat korporat dipantau penyerang (misalnya AD atau mailbox admin sudah dikuasai), koordinasi pindah ke grup Signal "JAB-CSIRT-OOB" dan conference bridge NOC. NCSC menyarankan menyiapkan kanal aman atau alternatif untuk insiden sensitif dan untuk kondisi ketika email, jaringan, atau telepon tidak bisa dipakai, dan menyimpan minimal 2 metode kontak untuk minimal 2 orang per fungsi [S3]. Matriks lengkap PT JAB ada di bagian 2.3.

### 1.5 On-call: orang yang siap, dengan akses yang sudah disiapkan

Malam itu PT JAB sebenarnya punya orang yang mampu menangani web shell: Dimas, Sari, dan Yoga. Yang tidak ada adalah jadwal yang menyebut siapa di antara mereka yang wajib mengangkat telepon Sabtu dini hari, dan nomor yang bisa ditemukan L1 dalam satu menit.

NIST r2 mencatat bahwa sebagian besar organisasi butuh staf IR yang tersedia 24/7, biasanya bisa dihubungi lewat telepon, dan bahwa tim paruh waktu bekerja seperti pemadam kebakaran sukarela: anggota dihubungi cepat saat darurat dan yang bisa membantu ikut turun [S2]. Model itu persis CSIRT virtual PT JAB. Konsekuensinya, kesiapan harus dirancang, karena tidak ada yang duduk menunggu di ruang SOC.

Jadwal on-call yang berguna punya empat komponen:

1. **Primary dan secondary per fungsi.** Selalu ada cadangan; PagerDuty menyarankan shift cadangan langsung setelah shift primary, dan level eskalasi ketiga adalah seluruh tim [S6]. NCSC menekankan deputi dan wewenang yang didelegasikan bila kontak utama tidak tersedia [S3]. Executive sponsor juga butuh delegasi tertulis saat cuti; tanpa itu, keputusan mematikan layanan tidak punya pemilik.
2. **Akses yang sudah diuji sebelum shift.** On-call tanpa akses tidak berguna. Untuk PT JAB: VPN dengan MFA dan metode MFA cadangan, akses Splunk ES, konsol EDR dengan hak isolasi host, akses ke server Linux lewat `jkt-bastion01`, dan prosedur memakai akun break-glass. PagerDuty memasukkan kesiapan lingkungan kerja (laptop, koneksi cadangan, kredensial yang masih berlaku, notifikasi yang menembus mode Do Not Disturb) sebagai prasyarat on-call [S6].
3. **Kontak luar yang siap dipakai.** Nomor hotline retainer PT Forensik Digital Contoh, nomor kontrak, dan NDA yang sudah ditandatangani. NIST r3 menyarankan menghubungi penyedia layanan IR bila perlu setelah insiden dinyatakan [S1], dan itu hanya cepat bila kontaknya sudah ada di jadwal, bukan dicari di email lama.
4. **Rotasi dan batas kelelahan.** NIST r2 menyebut pekerjaan IR dan tanggung jawab on-call sangat menekan, sehingga anggota tim mudah kelelahan [S2]. Google SRE menyarankan merotasi orang ke berbagai peran supaya semua terbiasa [S4]. PT JAB menulis aturan sederhana: tidak ada yang menjadi primary dua minggu berturut-turut, orang yang dipanggil lebih dari 2 jam antara 00:00 dan 06:00 masuk kerja siang, dan IC tidak memegang komando lebih dari 12 jam berturut-turut.

Akun break-glass perlu penjelasan sendiri. Saat AD diduga dikuasai atau MFA bermasalah, admin bisa terkunci dari sistemnya sendiri. Akun break-glass adalah akun darurat berhak tinggi yang kredensialnya disimpan tersegel (di vault dengan akses darurat tercatat, atau amplop di brankas), dipakai hanya bila jalur normal tidak bisa dipakai, dan setiap pemakaiannya memicu alert serta review. Akun ini juga harus diuji berkala; akun darurat yang passwordnya ternyata kedaluwarsa baru ketahuan saat insiden. Jadwal dan daftar akses PT JAB ada di bagian 2.4.

### 1.6 Handover shift dan serah terima peran IC

Shift pagi 12 September menerima satu kalimat: "masih investigasi". Mereka tidak tahu IP sudah diblokir, tidak tahu hipotesis jalur masuk sudah diuji, dan tidak tahu bahwa server sengaja belum di-restart karena menunggu pengambilan bukti. Hasilnya 2 jam 15 menit analisis ulang, dan permintaan blokir ganda ke NOC.

Handover shift NOC biasanya cukup berisi status tiket karena gangguan jaringan relatif jelas: link putus, tiket vendor terbuka, ETA sekian. Insiden keamanan berbeda karena sebagian besar nilai pekerjaan ada di kepala orang: hipotesis yang sedang diuji, alasan sebuah keputusan diambil, dan hal yang sengaja belum dilakukan supaya penyerang tidak sadar atau bukti tidak hilang. Bila hal-hal itu tidak diserahkan, shift berikutnya bisa membatalkan keputusan yang disengaja.

NIST r3 menyarankan status setiap insiden dilacak bersama ringkasan insiden, IOC terkait, status dan kerangka waktu setiap tindakan yang ditugaskan, serta langkah berikutnya [S1]. Google SRE menyebut dokumen status insiden yang hidup sebagai tugas terpenting IC: bisa diedit beberapa orang sekaligus, informasi kunci di bagian atas, dan disimpan untuk post-mortem [S4]. Handover adalah ringkasan dokumen itu pada satu titik waktu. Tabel berikut adalah isi wajib handover di PT JAB; kolom kanan menjelaskan apa yang hilang bila baris itu tidak ada.

| Isi | Kenapa wajib |
|---|---|
| Status dan severity saat ini, beserta alasan severity | Penerima tahu target waktu dan ritme update yang berlaku |
| Fakta terkonfirmasi dengan waktu dan sumbernya | Penerima tidak mengulang analisis yang sudah selesai |
| Hipotesis aktif, bukti pendukung, dan yang belum diuji | Penerima melanjutkan pengujian, bukan memulai dari nol |
| Keputusan yang sudah diambil, oleh siapa, dan alasannya | Keputusan tidak dibatalkan tanpa sengaja; alasannya bisa dinilai ulang bila kondisi berubah |
| Hal yang sengaja belum dilakukan, dan alasannya | Mencegah tindakan yang merusak bukti atau memberi tahu penyerang terlalu dini |
| Tindakan yang sedang berjalan: siapa, sampai kapan | Tidak ada tugas yatim; penerima tahu siapa yang harus ditagih |
| Siapa menunggu kabar dan kapan update berikutnya | Ritme update ke pimpinan dan DPO tidak terputus |
| Lokasi catatan: kanal, tiket, timeline scribe | Penerima tahu sumber kebenaran |

Handover dilakukan lisan dan tertulis. Lisan untuk tanya jawab, tertulis supaya tercatat di tiket dan bisa dibaca ulang. PagerDuty menyebut ringkasan lisan biasanya cukup untuk handover on-call rutin [S6]; untuk insiden aktif, PT JAB mewajibkan versi tertulis karena catatan IR bisa menjadi bukti dan bahan post-incident review.

Serah terima peran IC punya aturan tambahan, karena kebingungan soal siapa yang memimpin lebih berbahaya daripada kehilangan konteks. Google SRE menulis urutan yang jelas: IC baru di-brief penuh dulu (telepon atau video bila jarak jauh), IC lama bertanya secara eksplisit apakah IC baru sudah memegang komando, IC lama tidak pergi sebelum ada konfirmasi tegas, lalu semua orang diberi tahu [S4]. PagerDuty menambahkan: IC lama memberi konteks lewat kanal terpisah dulu, lalu mengumumkan di call bahwa komando diserahkan ke nama tertentu, dan IC baru mengumumkan dirinya beserta deputi dan scribe-nya, yang lalu dicatat di kanal insiden [S7][S8]. Alasan serah terima yang wajar antara lain IC kelelahan, kompleksitas insiden berubah, atau keadaan darurat pribadi [S7].

Dua aturan yang sering mengejutkan orang baru. Pertama, kedatangan orang yang lebih senior atau lebih ahli tidak otomatis memindahkan komando [S7]. Bila Direktur Teknologi masuk ke bridge dan mulai memberi perintah teknis, IC bertanya apakah ia ingin mengambil alih komando; bila tidak, IC tetap memimpin [S7]. Kedua, IC tidak ikut mengerjakan analisis atau remediasi, supaya tetap bisa melihat gambaran besar [S7]. Template dan contoh handover ada di bagian 2.5.

### 1.7 Plan yang tidak diuji akan gagal di titik yang sama

`JAB-IRP-01` versi 1.2 disetujui tahun 2023 dan tidak pernah diuji. Kalau satu kali saja ada orang yang mencoba menelepon kontak di plan itu jam dua pagi, kelemahan email-only sudah ketahuan sebelum insiden.

NIST r2 meminta plan direview minimal setahun sekali setelah disetujui [S2]. NIST r3 memindahkan urusan perencanaan ke kategori Improvement (ID.IM) di fungsi Identify: ID.IM-04 meminta IR plan dan rencana keamanan lain yang memengaruhi operasi ditetapkan, dikomunikasikan, dipelihara, dan diperbaiki, dengan prioritas High di profil IR [S1]. Pemakaiannya ada di fungsi Respond: RS.MA-01 menyatakan IR plan dijalankan bersama pihak ketiga terkait setelah insiden dinyatakan [S1]. Rekomendasinya: review berkala atau saat ada kebutuhan perbaikan yang signifikan, sesuaikan plan dengan kebutuhan unik organisasi, dan selaraskan dengan business continuity plan [S1]. Sumber perbaikannya menurut r3 ada tiga: evaluasi (ID.IM-01), latihan dan pengujian termasuk bersama pemasok dan pihak ketiga (ID.IM-02), dan pelaksanaan nyata termasuk rapat lessons learned setelah insiden (ID.IM-03) [S1].

Untuk PT JAB, pengujian dibagi tiga tingkat dari yang paling murah:

1. **Uji kontak (page test).** Setiap Senin, on-call baru ditelepon uji oleh scribe; waktu jawab dicatat. Ini menguji matriks eskalasi tanpa insiden.
2. **Uji akses.** Setiap kuartal, on-call membuktikan bisa login ke EDR, Splunk ES, dan `jkt-bastion01` dari luar kantor, dan akun break-glass diuji dengan prosedur resmi.
3. **Tabletop exercise.** Diskusi skenario untuk menguji keputusan dan komunikasi, bukan kemampuan mengetik perintah; desain, inject, dan fasilitasinya dibahas di Day 20 bagian 1.2 sampai 1.6.

Setiap SEV-1 dan SEV-2 juga menjadi uji nyata: post-incident review wajib menjawab "bagian mana dari plan yang dipakai, yang diabaikan, dan yang menghambat". Post-incident review 22 September menjawab pertanyaan itu untuk versi 1.2, dan dari jawabannya versi 2.0 disusun.

## 2. Contoh artefak dan langkah praktis di PT JAB

Semua artefak di bagian ini fiktif: nama orang, nomor dokumen, jadwal, dan isi timeline dibuat untuk latihan. Kelimanya adalah jawaban tertulis atas enam pertanyaan Hendra di bagian Ide inti.

### 2.1 Outline JAB-IRP-01 versi 2.0

Outline ini menjawab pertanyaan 1 dan 6 Hendra. Perhatikan bahwa butir 2 outline (wewenang) ditulis sebelum langkah apa pun, dan bahwa detail yang sering berubah dipindah ke lampiran.

```
JAB-IRP-01  Rencana Penanganan Insiden Keamanan Informasi PT JAB
Versi 2.0 | Disetujui: Hendra Wijaya, Direktur Teknologi | Pemilik dokumen: Dimas Prasetyo, SOC lead
Menggantikan versi 1.2 (2023) | Review berikutnya: Oktober 2027, atau setelah setiap SEV-1/SEV-2

1. Tujuan dan scope
   Semua sistem dan data PT JAB: kantor pusat, data center Jakarta, POP Bandung, Surabaya, Medan,
   layanan pelanggan (broadband, dedicated, portal, billing), dan sistem PT JAB yang dikelola pihak ketiga.
2. Wewenang
   2.1 IC (default: SOC lead) menyatakan insiden SEV-1 sampai SEV-4 atas usulan L2 on-call yang
       memvalidasi, dan boleh menaikkan atau menurunkan severity. Bila L2 tidak terjangkau sesuai
       matriks eskalasi, IC boleh memvalidasi sendiri.
   2.2 IC on-call boleh memerintahkan, tanpa change approval rutin: blokir IOC terkonfirmasi di firewall
       perimeter dan proxy, isolasi host internal lewat EDR atau port switch, disable dan reset akun
       termasuk akun privileged. NOC dan Infrastruktur menjalankannya sebagai change darurat;
       change dicatat di tiket insiden dan ditinjau di jam kerja berikutnya.
   2.3 Mematikan atau memutus layanan pelanggan (portal, RADIUS, billing, DNS resolver) hanya oleh
       executive sponsor atau delegasi tertulisnya, atas rekomendasi IC.
   2.4 Pihak luar: retainer diaktifkan oleh IC; regulator dan subjek data dihubungi DPO atas persetujuan
       executive sponsor; media dan publik hanya lewat Corporate Communication.
   2.5 Aturan cadangan: bila IC tidak bisa dihubungi sesuai matriks eskalasi, backup IC (L2 senior
       on-call) memegang wewenang 2.1 dan 2.2, termasuk menyatakan insiden. Wewenang 2.3 tidak ikut
       pindah; bila executive sponsor tidak terjangkau, keputusan itu dipegang delegasi tertulisnya.
3. Definisi dan severity
   Event, insiden, dan skala SEV-1 sampai SEV-4 beserta target waktu. Bila ragu antara dua tingkat,
   pilih yang lebih tinggi lalu turunkan setelah ada bukti; setiap perubahan dicatat beserta alasannya.
4. Peran dan RACI                        -> Lampiran A
5. Eskalasi dan on-call                  -> Lampiran B (matriks), Lampiran C (jadwal dan akses)
6. Komunikasi
   Paging lewat telepon. Kanal insiden #inc-2026-NNN dibuka saat declare. Kanal OOB: grup Signal
   "JAB-CSIRT-OOB" dan conference bridge NOC, dipakai bila email/chat diduga dipantau penyerang.
   Ritme update ke executive sponsor sesuai severity. Handover tertulis wajib (Lampiran D).
7. Kewajiban pelaporan
   Insiden yang menyangkut data pribadi pelanggan dinilai DPO dan Legal untuk kewajiban UU PDP;
   kewajiban ke regulator sektor dan kontrak pelanggan korporat dinilai Legal. Prosedur rinci terpisah.
8. Daftar playbook
   JAB-PB-01 Ransomware | JAB-PB-02 Phishing dan BEC | JAB-PB-03 Kompromi akun |
   JAB-PB-04 Kompromi aplikasi web dan web shell (baru, dari pelajaran INC-2026-012)
9. Pengujian, review, dan hubungan dengan rencana lain
   Uji kontak mingguan, uji akses kuartalan, tabletop minimal sekali setahun, review setelah setiap
   SEV-1/SEV-2. Diselaraskan dengan BCP dan DRP layanan pelanggan.
10. Lampiran
   A RACI | B Matriks eskalasi | C Jadwal on-call dan daftar akses | D Template handover |
   E Daftar kontak (2 orang, 2 metode per fungsi) | F Template laporan insiden
```

Tabel berikut memetakan elemen outline ke masalah yang ditemukan post-incident review; baca kolom kanan untuk memastikan setiap masalah punya jawaban di dokumen.

| Elemen | Masalah 12 September yang dijawab |
|---|---|
| Butir 2.2 (wewenang di muka untuk blokir dan isolasi) | NOC menolak memblokir karena tidak ada yang berwenang memerintah |
| Butir 2.3 (layanan pelanggan tetap di executive sponsor) | Mencegah wewenang di muka dipakai untuk keputusan bisnis besar |
| Butir 2.5 (backup IC memegang wewenang) | Insiden tidak berhenti saat IC tidak bisa dihubungi |
| Butir 6 (paging lewat telepon, handover tertulis wajib) | L1 menunggu email 50 menit; handover satu kalimat |
| Butir 9 (uji kontak, uji akses) | Versi 1.2 tidak pernah diuji |
| Lampiran dipisah | Nomor telepon bisa diperbarui mingguan tanpa persetujuan direktur |

### 2.2 RACI aktivitas IR PT JAB (Lampiran A)

RACI ini menjawab pertanyaan 2 Hendra. Baca per baris: setiap aktivitas punya tepat satu A. Singkatan kolom: L2/TL adalah L2 on-call sebagai technical lead; Dir. Tek adalah Direktur Teknologi sebagai executive sponsor; "-" berarti tidak terlibat.

| Aktivitas | L1 | L2/TL | IC | Dir. Tek | NOC/Infra | Legal | DPO | Corp Comm |
|---|---|---|---|---|---|---|---|---|
| Menyatakan insiden (declare) | C | R | A | I (SEV-1/2) | I | - | - | - |
| Menaikkan atau menurunkan severity | C | R | A | I | I | - | I (data pribadi) | - |
| Blokir IOC di firewall perimeter | I | C | A | - | R | - | - | - |
| Isolasi host internal (EDR atau port switch) | I | R | A | I | R | - | - | - |
| Disable atau reset akun privileged | I | C | A | I | R | - | - | - |
| Mematikan layanan pelanggan (portal, RADIUS, billing, DNS resolver) | - | C | C | A | R | C | I | C |
| Mengaktifkan retainer (dalam kuota kontrak) | - | C | A/R | I | - | I | - | - |
| Notifikasi ke regulator dan subjek data | - | C | C | A | - | C | R | C |
| Pernyataan publik dan jawaban ke media | - | - | C | A | - | C | C | R |
| Menutup insiden | I | R | A | I | C | C | C | I |

Cara membaca elemen pentingnya:

- **Blokir IOC:** IC adalah A dan NOC adalah R. Ini kebalikan dari kondisi 12 September, ketika NOC secara de facto memegang A. NOC tetap boleh menolak bila perintahnya berisiko merusak layanan (misalnya memblokir rentang IP milik pelanggan korporat); penolakan itu dicatat dan dibawa ke IC, bukan didiamkan.
- **Isolasi host:** dua R karena eksekusinya bisa lewat EDR (L2) atau port switch (NOC). Bila host yang diisolasi langsung melayani pelanggan, seperti `jkt-portal01`, tindakan itu sama dengan mematikan layanan pelanggan dan pindah ke baris keenam.
- **Mematikan layanan pelanggan:** IC hanya C. IC menyiapkan rekomendasi dan risikonya, Direktur Teknologi memutuskan, NOC menjalankan.
- **Retainer:** IC boleh mengaktifkan selama masih dalam kuota jam kontrak. Penambahan biaya di luar kuota adalah keputusan pembayaran ke pihak ketiga dan menjadi A Direktur Teknologi.
- **Notifikasi regulator:** DPO adalah R karena memahami kewajiban UU PDP, tetapi A tetap di Direktur Teknologi karena yang melapor adalah perusahaan. Rinciannya dibahas di Day 18 bagian 1.4 dan 1.5.

**Kapan gagal:** RACI ini gagal bila nama orang di balik setiap kolom tidak jelas pada malam tertentu. Kolom "IC" berarti IC on-call minggu itu, bukan selalu Dimas; karena itu RACI selalu dibaca bersama jadwal on-call di bagian 2.4.

### 2.3 Matriks eskalasi PT JAB (Lampiran B)

Matriks ini menjawab pertanyaan 3 Hendra. L1 tidak perlu yakin bahwa sesuatu adalah insiden untuk menelepon; cukup cocok dengan salah satu baris. Kolom "Bila tidak dijawab" adalah bagian yang tidak ada di versi 1.2.

| Pemicu | Severity minimum | Siapa dihubungi | Lewat apa | Batas waktu | Bila tidak dijawab |
|---|---|---|---|---|---|
| Malware atau kompromi pada satu endpoint atau akun biasa, tanpa tanda penyebaran | SEV-3 | Antrean L2 | Tiket SOC; di luar jam kerja cukup tiket | Jam kerja berikutnya | Naik ke baris lain bila ada tanda penyebaran |
| Kompromi terkonfirmasi pada server, termasuk web shell atau backdoor | SEV-2 | L2 on-call (validasi dan usul declare), lalu L2 menelepon IC | Telepon, lalu IC membuka `#inc-2026-NNN` | L2 menjawab maks 5 menit; IC aktif maks 30 menit | 5 menit: L1 menelepon IC langsung; 15 menit: backup IC; 25 menit: Direktur Teknologi |
| Akun privileged disalahgunakan (`adm.*`, domain admin, `svc_*`) | SEV-2 | L2 on-call, lalu IC; IC memanggil Infrastruktur on-call | Telepon | IC aktif maks 30 menit | Sama dengan baris di atas |
| Data pribadi pelanggan mungkin terdampak | SEV-2 | IC; IC memberi tahu DPO dan Legal | Telepon | DPO dan Legal tahu pada update pertama, maks 4 jam setelah declare | IC menghubungi delegasi DPO |
| Sistem kritis ISP terkompromi (`jkt-radius01`, `jkt-billing01`, DNS resolver) | SEV-2; SEV-1 bila layanan terganggu luas | IC dan Manajer NOC; untuk SEV-1 juga Direktur Teknologi | Telepon dan conference bridge NOC | SEV-1: IC 15 menit, Direktur 30 menit | 5 menit: backup masing-masing |
| Ransomware menyebar, domain admin dikuasai, atau kebocoran data besar | SEV-1 | L2 on-call dan IC bersamaan; IC memanggil Direktur Teknologi dan Manajer NOC, serta menilai pemanggilan retainer | Telepon; Signal "JAB-CSIRT-OOB" bila AD atau email diduga dikuasai | IC 15 menit, Direktur 30 menit | 5 menit: backup IC; 10 menit: Direktur Teknologi langsung |
| Media atau pelanggan korporat menanyakan insiden | SEV-2 | IC, Corporate Communication, Direktur Teknologi | Telepon | 30 menit | Staf lain tidak menjawab media; semua diarahkan ke Corp Comm |
| Butuh forensik di luar kemampuan internal | Sesuai insiden | Retainer PT Forensik Digital Contoh, oleh IC | Hotline retainer, lalu email konfirmasi | Sesuai SLA kontrak | Kontak cadangan di kontrak retainer |

Cara membaca hasilnya untuk malam 12 September, bila matriks ini sudah berlaku:

```
01:52  L1 cocokkan dengan baris "kompromi server, web shell"   -> SEV-2
01:52  telepon L2 on-call (primary)                              menit 0
01:57  tidak diangkat -> L1 telepon IC on-call langsung          menit 5
02:07  tidak diangkat -> telepon backup IC                       menit 15
02:17  tidak diangkat -> telepon Direktur Teknologi              menit 25
02:22  batas terakhir IC aktif                                   menit 30
       (bila L2 mengangkat di menit 0, L2 memvalidasi lalu menelepon IC)
```

Waktu dihitung dari 01:52, saat L1 menilai alert memenuhi pemicu. Pada skenario terburuk IC aktif paling lambat 02:22, 20 menit lebih cepat daripada telepon pertama yang sebenarnya (02:42) dan 33 menit lebih cepat daripada declare yang sebenarnya (02:55).

**Variasi:** organisasi dengan SOC yang dikelola MSSP perlu satu baris tambahan untuk eskalasi dari MSSP ke on-call internal, termasuk batas apa yang boleh dilakukan MSSP sendiri. NIST r3 menyarankan pembagian tanggung jawab dengan penyedia layanan ditulis jelas di kontrak, termasuk wewenang bertindak atas nama organisasi [S1].

**Kapan gagal:** matriks gagal bila kontak di dalamnya tidak pernah diuji (nomor lama, telepon kantor yang tidak dibawa pulang), atau bila L1 merasa takut "membangunkan direktur untuk hal kecil". Kalimat di plan yang menyatakan bahwa eskalasi sesuai matriks tidak pernah disalahkan, walau ternyata false positive, sama pentingnya dengan matriksnya. PagerDuty menulis prinsip yang sama untuk on-call: jangan ragu melakukan eskalasi [S6].

### 2.4 Jadwal on-call dan kesiapan akses (Lampiran C)

Jadwal ini menjawab pertanyaan 4 Hendra. Contohnya untuk minggu 12 sampai 18 Oktober 2026; serah terima mingguan dilakukan Senin 09:00. Rudi Hartanto adalah analyst L2 ketiga yang masuk rotasi setelah review 22 September, supaya backup IC dan secondary L2 tidak dipegang orang yang sama.

| Fungsi | Primary | Secondary | Cara dihubungi | Akses yang harus sudah diuji sebelum shift |
|---|---|---|---|---|
| IC | Dimas Prasetyo (SOC lead) | Yoga Pratama (L2 senior, backup IC) | Telepon, lalu `#inc-2026-NNN` | Splunk ES dan ticketing, hak membuka kanal insiden, daftar kontak Lampiran E di ponsel |
| L2 / technical lead | Sari Kusuma | Rudi Hartanto | Telepon | VPN dengan MFA dan metode MFA cadangan, Splunk ES, konsol EDR dengan hak isolasi, `jkt-bastion01` |
| NOC dan Infrastruktur | Engineer NOC shift (24/7 di tempat) | Manajer NOC Bambang Hartono | Conference bridge NOC | Konsol firewall perimeter, switch data center, prosedur akun break-glass AD |
| Executive sponsor | Hendra Wijaya | Delegasi tertulis bila cuti (nama dicatat di jadwal) | Telepon | - |
| Retainer | Hotline PT Forensik Digital Contoh | Kontak akun retainer | Telepon dan email | Nomor kontrak, NDA, sisa kuota jam |

Aturan rotasi yang ditulis di bawah tabel:

- Tidak ada yang menjadi primary dua minggu berturut-turut.
- Satu orang tidak memegang dua fungsi berbeda di minggu yang sama, supaya saat SEV-1 memanggil semua fungsi sekaligus tidak ada kursi yang kosong.
- Orang yang dipanggil lebih dari 2 jam antara 00:00 dan 06:00 masuk kerja siang.
- IC tidak memegang komando lebih dari 12 jam berturut-turut; serah terima dijadwalkan, bukan menunggu IC tertidur.
- Tukar jadwal dicatat di jadwal resmi, bukan hanya di chat, supaya L1 tidak menelepon orang yang sedang cuti.

**Cara membaca hasil uji kontak:** setiap Senin 09:15 scribe menelepon semua primary dan secondary. Catat waktu jawab. Kontak yang tidak menjawab dalam batas timeout matriksnya diperbaiki hari itu juga (nomor salah, notifikasi tidak menembus Do Not Disturb, ponsel kantor tidak dibawa).

**Kapan gagal:** jadwal gagal bila hanya ada di wiki atau share yang ikut mati saat insiden. Simpan salinannya di tempat yang tetap bisa dibuka saat jaringan kantor bermasalah, misalnya ponsel on-call dan grup OOB.

### 2.5 Template handover dan contoh buruk vs baik (Lampiran D)

Template ini menjawab pertanyaan 5 Hendra. Contoh buruknya adalah handover yang benar-benar terjadi pada 07:00 tanggal 12 September; contoh baiknya adalah handover yang seharusnya ditulis malam itu dari fakta yang sudah diketahui.

Template:

```
HANDOVER <nomor insiden> | <severity> | <tanggal dan jam WIB>
Dari: <nama, peran>          Ke: <nama, peran>          IC saat ini: <nama>
1. Status dan severity (alasan severity)
2. Fakta terkonfirmasi (jam, sumber)
3. Hipotesis aktif (bukti, yang belum diuji)
4. Keputusan yang sudah diambil (jam, siapa, alasan)
5. Sengaja BELUM dilakukan (alasan)
6. Tindakan berjalan (siapa, sampai kapan)
7. Menunggu kabar (siapa, update berikutnya jam berapa)
8. Lokasi catatan (kanal, tiket, timeline)
Konfirmasi penerima: <nama, jam>
```

Contoh buruk (yang benar-benar dikirim):

```
07:00 [#soc-shift] Shift malam ke pagi: INC-2026-012 portal masih investigasi. Detail di channel. Thx
```

Kanal insiden saat itu berisi lebih dari 300 pesan. "Detail di channel" memindahkan beban membaca ke penerima, tanpa memberi tahu mana yang fakta, mana dugaan, dan mana yang sudah diputuskan.

Contoh baik (yang seharusnya ditulis):

```
HANDOVER INC-2026-012 | SEV-2 | 2026-09-12 07:00 WIB
Dari: L1 shift malam (scribe) dan Dimas Prasetyo (IC)    Ke: Sari Kusuma (technical lead, shift pagi)
IC saat ini: Dimas Prasetyo; diserahkan ke Yoga Pratama pukul 09:00 (terjadwal)

1. Status: SEV-2 sejak 02:55 (server pelanggan terkompromi, data pribadi mungkin terdampak).
   Containment parsial: 198.51.100.23 diblok di firewall perimeter 04:31.
2. Fakta:
   - 01:38 file shell.php dibuat proses web server di /var/www/portal/uploads/ (log server)
   - 01:41 sampai 04:29: 12 request POST ke shell.php, semua dari 198.51.100.23 (access log)
   - Tidak ada request ke shell.php setelah 04:31 (dicek sampai 06:45)
3. Hipotesis:
   - H1 (didukung): masuk lewat fitur unggah dokumen portal; file dibuat 01:38 oleh proses web server
   - H2 (belum diuji): penyerang membaca database pelanggan memakai kredensial di file config portal
4. Keputusan:
   - 02:55 Dimas: declare SEV-2
   - 03:00 Dimas: tidak merekomendasikan mematikan portal; blokir IP dinilai cukup sementara,
     dampak mematikan portal ke pelanggan dinilai lebih besar. Ditinjau ulang bila H2 terbukti.
   - 05:10 Dimas: aktifkan retainer PT Forensik Digital Contoh untuk akuisisi memori dan disk
5. Sengaja BELUM dilakukan:
   - jkt-portal01 belum di-restart dan shell.php belum dihapus: menunggu akuisisi memori dan disk.
     Jangan restart layanan walau portal lambat; hubungi IC dulu.
   - Kredensial database portal belum dirotasi: menunggu hasil uji H2, supaya scoping tidak terganggu.
6. Berjalan:
   - Retainer tiba 10:00 (kontak di Lampiran E)
   - Query akses database dari jkt-portal01 24 jam terakhir: dimulai Sari 07:15, target 09:00
7. Menunggu kabar:
   - Hendra Wijaya: update terakhir 06:50, berikutnya 10:50
   - Agus Setiawan (DPO) dan Ratna Sari (Legal): diberi tahu 06:50, menunggu hasil H2
8. Catatan: #inc-2026-012, tiket INC-2026-012 (timeline scribe), alert SOC-2026-0127
Konfirmasi penerima: Sari Kusuma, 07:12
```

Tabel berikut menunjukkan kenapa tiap bagian template ada; saat menulis handover sendiri, cek apakah setiap baris kolom kiri terisi.

| Elemen | Fungsinya pada pagi 12 September |
|---|---|
| Fakta dengan jam dan sumber | Sari tidak perlu mengulang analisis 07:15 sampai 09:30 |
| Blokir 04:31 ditulis di status | Tidak ada permintaan blokir ganda ke NOC |
| Hipotesis H2 ditandai belum diuji | Sari langsung tahu pekerjaan pertama hari itu |
| Bagian "sengaja belum dilakukan" | Mencegah restart yang menghapus bukti di memori |
| Jam update berikutnya | Ritme update SEV-2 (setiap 4 jam) ke Direktur Teknologi tidak putus |
| Konfirmasi penerima | Ada bukti handover diterima, bukan hanya dikirim |

**Variasi:** untuk serah terima peran IC pukul 09:00, handover tertulis yang sama dipakai, ditambah urutan dari bagian 1.6: Yoga di-brief lewat telepon, Dimas bertanya "Yoga, kamu sekarang IC?", menunggu jawaban tegas, lalu menulis di `#inc-2026-012`: "Mulai 09:04 IC INC-2026-012 adalah Yoga Pratama." Scribe mencatat perubahan itu di timeline.

**Kapan gagal:** handover gagal bila ditulis di menit terakhir oleh orang yang sudah kelelahan. Karena itu dokumen status insiden diperbarui sepanjang shift, dan handover tinggal merangkumnya.

## 3. Lab praktik

Latihan Day ini berupa dokumen untuk PT JAB atau organisasi fiktif buatanmu sendiri. Jangan memakai nama, nomor, atau struktur tempat kerja nyata.

1. **Mencari celah di plan contoh.** Berikut kutipan bagian eskalasi `JAB-IRP-01` versi 1.2 yang berlaku pada 12 September. Temukan minimal enam celah, dan untuk setiap celah tulis bagian mana dari timeline Ide inti yang disebabkannya.

   ```
   JAB-IRP-01 versi 1.2 (2023), bagian 5: Eskalasi
   5.1 Insiden keamanan dilaporkan ke Tim Keamanan melalui email security@jab.example.
   5.2 Tim Keamanan dan Manajer NOC bersama-sama memutuskan tindakan containment.
   5.3 Perubahan konfigurasi firewall mengikuti prosedur change management yang berlaku.
   5.4 Daftar kontak tersedia di wiki SOC.
   5.5 Rencana ini ditinjau bila diperlukan.
   ```

2. **Menyusun RACI.** Buat RACI untuk organisasimu (minimal 8 aktivitas, minimal 6 kolom peran). Lalu jalankan tiga pengecekan dari bagian 1.3: tepat satu A per baris, minimal satu R per baris, dan tidak ada kolom yang penuh A.
3. **Menyusun matriks eskalasi.** Buat matriks dengan minimal enam pemicu, termasuk satu pemicu jenis data, satu pemicu jenis akun, dan satu pemicu pihak luar. Untuk setiap baris SEV-1 dan SEV-2, hitung skenario terburuk sampai IC aktif (jumlahkan semua timeout) dan bandingkan dengan target severity-nya.
4. **Menulis handover.** Pakai skenario latihan berikut. Kamu analyst L2 shift sore yang menyerahkan ke shift malam pukul 23:00:
   - 17:20 alert login `fitri.handayani` ke webmail dari `198.51.100.23` setelah email phishing pukul 16:55.
   - 17:45 ditemukan inbox rule baru yang memindahkan email berisi kata "invoice" ke folder RSS.
   - 18:10 IC (Dimas) menyatakan SEV-3; sesi dicabut dan password direset pukul 18:30.
   - 19:40 ditemukan email phishing yang sama di 14 mailbox lain; 2 pengguna mengklik tautan. Dimas menaikkan ke SEV-2 pukul 19:55.
   - Dimas memutuskan belum menghapus email phishing dari 14 mailbox sampai daftar penerima lengkap diekspor, supaya bukti tidak hilang. Ekspor sedang berjalan oleh Sari, perkiraan selesai 23:30.
   - Belum diketahui apakah 2 pengguna yang mengklik juga memasukkan password.

   Tulis handover memakai template bagian 2.5, termasuk bagian "sengaja belum dilakukan" dan jam update berikutnya untuk SEV-2.
5. **Serah terima IC.** Tulis naskah singkat (lisan dan pesan di kanal insiden) untuk menyerahkan komando dari IC yang sudah memimpin 11 jam ke backup IC, mengikuti urutan bagian 1.6.
6. **Uji kontak di atas kertas.** Untuk matriks dari langkah 3, tulis daftar hal yang harus dicek pada uji kontak mingguan dan uji akses kuartalan, termasuk akun break-glass.

**Hasil yang sebaiknya tersimpan:**
- `latihan/day02-celah-irp.md`: minimal enam celah, masing-masing dipetakan ke kejadian di timeline dan ke elemen yang hilang di tabel bagian 1.2.
- `latihan/day02-raci-eskalasi.md`: RACI yang lolos tiga pengecekan, matriks eskalasi dengan hitungan skenario terburuk yang tidak melewati target severity.
- `latihan/day02-handover.md`: handover skenario langkah 4 yang memisahkan fakta, hipotesis, keputusan, dan hal yang sengaja belum dilakukan, serta naskah serah terima IC dari langkah 5.
- Satu paragraf: celah mana dari langkah 1 yang menurutmu paling mahal, dan kenapa.

**Variasi tantangan:** ubah asumsi menjadi "Signal dan telepon kantor tidak bisa dipakai karena akun manajemen ponsel perusahaan diduga dikuasai penyerang". Kanal apa yang tersisa, dan siapa yang harus sudah menyimpan nomor pribadi siapa sebelum insiden?

## 4. Troubleshooting

Tabel ini memuat gejala yang paling sering muncul saat plan dipakai pertama kali; cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa atau memperbaiki |
|---|---|---|
| L1 tidak tahu harus menelepon siapa | Plan hanya menyebut tim atau email, bukan peran on-call dan nomor | Matriks eskalasi per pemicu; daftar kontak 2 orang dan 2 metode per fungsi [S3] |
| Telepon tidak diangkat dan L1 terus menunggu | Tidak ada timeout eskalasi | Tulis "bila tidak dijawab N menit, telepon X"; hitung mundur dari target severity |
| Tim operasional menolak menjalankan containment | Wewenang IC tidak tertulis atau kalah oleh prosedur change | Wewenang di muka di IR plan yang disetujui pejabat yang membawahi kedua tim |
| Dua orang memberi perintah bertentangan | Dua A untuk satu aktivitas, atau pimpinan masuk bridge tanpa serah terima komando | Cek RACI per baris; IC bertanya apakah pimpinan ingin mengambil alih komando [S7] |
| On-call tidak bisa login ke EDR atau VPN | Akses tidak diuji, MFA tanpa cadangan, akun dinonaktifkan | Uji akses kuartalan dan sebelum shift; metode MFA cadangan; akun break-glass yang teruji |
| Shift berikutnya mengulang analisis | Handover hanya status, tanpa fakta, hipotesis, dan keputusan | Template handover bagian 2.5; dokumen status insiden diperbarui sepanjang shift |
| Plan tidak dibuka saat insiden | Terlalu panjang, tersimpan di sistem yang ikut terdampak | Ringkasan satu halaman (wewenang, matriks, kontak) di ponsel on-call dan grup OOB |
| Chat korporat diduga dipantau penyerang | Akun admin atau mailbox sudah dikuasai | Pindah ke kanal OOB yang disiapkan sebelum insiden; jangan membahas containment di kanal lama |

## 5. Kesalahan umum dan jebakan

- Menganggap playbook cukup tanpa IR plan. Playbook menjawab "bagaimana", plan menjawab "siapa boleh" [S1][S2].
- Menulis wewenang terlalu umum ("Tim Keamanan berwenang menangani insiden"). Wewenang harus per tindakan: declare, blokir, isolasi, disable akun, mematikan layanan, menghubungi pihak luar [S1][S2].
- Menulis pemilik sistem sebagai Accountable atas containment. Pemilik sistem biasanya Responsible untuk eksekusi dan Consulted untuk risiko operasional.
- Memberi IC wewenang atas semua hal, termasuk mematikan layanan pelanggan. Keputusan berdampak bisnis besar tetap di pimpinan [S1].
- Memakai email atau chat untuk paging tengah malam. Email tidak membangunkan orang.
- Jadwal on-call tanpa akses yang diuji, tanpa secondary, atau tanpa delegasi executive sponsor saat cuti [S3][S6].
- Handover berisi status tiket saja. Yang paling mahal hilang adalah keputusan beserta alasannya dan hal yang sengaja belum dilakukan.
- Mengira pimpinan yang masuk ke bridge otomatis menjadi IC. Komando hanya pindah lewat serah terima eksplisit [S4][S7].
- Menganggap plan selesai setelah ditandatangani. NIST r2 meminta review minimal tahunan dan r3 meminta perbaikan berkelanjutan dari evaluasi, latihan, dan insiden [S1][S2].
- Menyalin daftar elemen r2 ke plan tanpa menyesuaikan. NIST r3 menekankan plan harus berdasar kebutuhan unik organisasi: misi, ukuran, struktur, dan fungsi [S1].

## 6. Catatan terkini

Bagian ini menampung detail edisi dan perubahan antar revisi NIST yang berguna saat membaca materi lain atau menjawab auditor, tetapi tidak mengubah isi plan PT JAB.

- NIST SP 800-61 Rev. 3 terbit April 2025 (disetujui Editorial Review Board 25 Maret 2025) dan menggantikan Rev. 2 (Agustus 2012) [S1]. Judulnya berubah dari Computer Security Incident Handling Guide menjadi Incident Response Recommendations and Considerations for Cybersecurity Risk Management, dengan subjudul CSF 2.0 Community Profile [S1].
- Change log r3 menyebut empat perubahan besar: penulisan ulang penuh untuk membuang materi usang, pergeseran fokus dari panduan menangani insiden ke integrasi IR dalam manajemen risiko, penyusunan ulang isi sebagai CSF 2.0 Community Profile, dan pemindahan sebagian besar tautan ke situs proyek SP 800-61 [S1].
- Daftar delapan elemen plan dari r2 (misi, strategi dan sasaran, persetujuan manajemen senior, dan seterusnya) tidak diulang di r3. Perencanaan IR di r3 masuk ke ID.IM-04 dengan prioritas High, sedangkan daftar elemen kebijakan tetap ada di section 2.3 dokumen r3 [S1][S2]. Lowongan kerja, kuesioner audit, dan materi pelatihan masih sering mengutip daftar r2, jadi keduanya perlu dikenali.
- Kebiasaan "review plan minimal setahun sekali" berasal dari r2 [S2]. Rumusan r3 adalah review berkala atau saat ada kebutuhan perbaikan signifikan [S1]. Review tahunan tetap praktik yang wajar dan dipakai di `JAB-IRP-01`.
- Tahap Preparation di siklus r2 dipetakan r3 ke fungsi Govern, Identify, dan Protect, sedangkan Post-Incident Activity dipetakan ke kategori Improvement (ID.IM) [S1]. Konsekuensinya, di r3 IR plan dan lessons learned berada di kategori yang sama.
- R3 memakai istilah incident lead (misalnya saran menunjuk incident lead untuk setiap insiden di RS.MA-01), bukan incident commander [S1]. Istilah incident commander berasal dari praktik incident management seperti Google SRE dan PagerDuty [S4][S5]. Di catatan ini keduanya dianggap peran yang sama.
- R3 mencantumkan legal, public affairs, HR, keamanan fisik, dan pemilik aset sebagai peran yang terlibat dalam IR, di luar incident handler [S1]. Ini sejalan dengan kolom RACI PT JAB.
- Halaman CISA untuk Federal Government Cybersecurity Incident and Vulnerability Response Playbooks tidak mencantumkan tanggal terbit; playbook ini disusun atas mandat Executive Order 14028 untuk instansi sipil federal AS [S10]. Tanggal edisinya perlu dicek di PDF-nya.

## 7. Cheat sheet

```
Lapisan dokumen:
  kebijakan IR (direksi)  -> IR plan (Direktur Teknologi) -> playbook/prosedur (SOC lead)
  lampiran operasional (kontak, on-call) dipisah, diperbarui mingguan

Isi IR plan minimal:
  tujuan+scope | WEWENANG per tindakan | definisi+severity | peran+RACI | eskalasi+on-call
  kanal (termasuk OOB) | kewajiban lapor | daftar playbook | uji+review | link ke BCP/DRP
  NIST r2: policy/plan/procedure elements | NIST r3: GV.RR-02, ID.IM-04, RS.MA-01/04, RS.CO-02

RACI: R mengerjakan | A pemilik keputusan (TEPAT SATU) | C dimintai pendapat | I diberi tahu
  pemilik sistem = R (eksekusi), bukan A atas containment
  mematikan layanan pelanggan = A executive sponsor, IC = C

Eskalasi:
  pemicu: severity | jenis data (data pribadi) | jenis akun (privileged) | sistem kritis | pihak luar
  escalation = tambah sumber daya/percepat ; elevation = libatkan manajemen lebih tinggi
  alur declare: L1 -> L2 on-call (validasi, usul) -> IC (declare); backup IC boleh declare bila IC tak terjangkau
  timeout mundur dari target: SEV-2 (IC 30 mnt) L2 0 / IC 5 / backup IC 15 / Dir 25
                              SEV-1 (IC 15 mnt) L2+IC 0 / backup IC 5 / Dir 10
  paging = telepon, bukan email ; OOB bila chat/email diduga dipantau

On-call: primary + secondary | akses diuji (VPN+MFA cadangan, EDR, SIEM, bastion, break-glass)
  kontak retainer siap | rotasi, batas kelelahan, IC maks 12 jam

Handover: status+alasan | fakta (jam, sumber) | hipotesis | keputusan (siapa, alasan)
  SENGAJA BELUM dilakukan | tindakan berjalan | siapa menunggu, update berikutnya | lokasi catatan
Serah terima IC: brief -> tanya eksplisit -> tunggu konfirmasi -> umumkan di kanal
Uji: page test mingguan | uji akses kuartalan | tabletop tahunan | review setelah SEV-1/2
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Seorang rekan berkata, "Kita sudah punya playbook web shell `JAB-PB-04` yang menulis 'blokir IP penyerang'. Jadi kejadian NOC menolak blokir tidak akan terulang, dan IR plan tidak perlu diubah." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Playbook menjawab "bagaimana", bukan "siapa boleh memerintahkan". NIST menempatkan prosedur di bawah kebijakan dan plan, dan wewenang (termasuk memutus atau mematikan aset) adalah elemen kebijakan dan plan. Malam itu NOC menolak karena prosedur change management mewajibkan persetujuan Manajer NOC dan tidak ada dokumen di atasnya yang memberi IC wewenang. Yang menyelesaikan masalah adalah wewenang di muka di IR plan yang disetujui Direktur Teknologi, bukan kalimat di playbook. Lihat bagian 1.1 dan 1.2.

</details>

**2. Skenario keputusan.** Saat merevisi RACI, tim berdebat soal baris "Blokir IOC di firewall perimeter". Pilihan mana yang tepat?

- A. Manajer NOC sebagai A dan R, karena NOC pemilik firewall.
- B. IC sebagai A, NOC sebagai R, L2 sebagai C.
- C. IC dan Manajer NOC sama-sama A, supaya keduanya merasa memiliki keputusan.

<details><summary>Jawaban</summary>

B. Keputusan containment ada di IC, eksekusinya di pemilik sistem, dan L2 memberi dasar teknis IOC-nya. A keliru karena R dan A tertukar: pemilik sistem menjadi pemilik keputusan containment, sehingga IC harus meminta izin setiap kali, persis kondisi 12 September. C keliru karena dua A berarti tidak ada pemilik; saat salah satunya tidak bisa dihubungi, keputusan berhenti. NOC tetap boleh menyampaikan keberatan operasional ke IC, dan keberatan itu dicatat. Lihat bagian 1.3 dan 2.2.

</details>

**3. Skenario keputusan.** Selasa 23:10, analyst L1 melihat akun admin `adm.rina` login ke `JKT-JUMP01` dari workstation `BDG-WS-0117` yang tidak pernah dipakai Rina, padahal Rina sedang cuti. L1 menelepon L2 on-call dan tidak diangkat, lalu pada menit 5 menelepon IC on-call; sampai menit 15 IC juga tidak mengangkat. Apa langkah yang tepat?

- A. Kirim email ke IC dan tunggu sampai pagi, karena belum pasti ini insiden.
- B. Telepon backup IC sesuai matriks, catat jam setiap panggilan, dan bila sampai menit 25 belum ada IC, telepon Direktur Teknologi.
- C. Disable `adm.rina` sendiri lewat konsol AD supaya penyerang langsung terhenti.

<details><summary>Jawaban</summary>

B. Penyalahgunaan akun privileged adalah pemicu SEV-2 minimum, dan matriks PT JAB untuk SEV-2 berurutan: L2 di menit 0, IC di menit 5, backup IC di menit 15, Direktur Teknologi di menit 25, sehingga IC tetap aktif paling lambat menit 30. Backup IC berwenang menyatakan insiden bila IC tidak terjangkau. A keliru karena email tidak membangunkan orang dan L1 tidak perlu yakin bahwa ini insiden untuk menelepon; cukup cocok dengan pemicu. C keliru karena disable akun privileged adalah tindakan dengan IC sebagai A dan Infrastruktur sebagai R, bukan L1. Bila kemudian terlihat akun itu dipakai menguasai domain admin, insiden naik ke SEV-1 dan timeout-nya menjadi 5 menit. Lihat bagian 1.4, 2.2, dan 2.3.

</details>

**4. Pertanyaan jebakan.** "Jadwal on-call minggu ini sudah lengkap: setiap fungsi punya primary dan secondary. Jadi kita siap." Apa yang belum tentu benar?

<details><summary>Jawaban</summary>

Nama di jadwal belum berarti orang itu bisa bekerja. On-call tanpa akses tidak berguna: VPN dengan MFA dan metode cadangan, konsol EDR dengan hak isolasi, SIEM, bastion, dan prosedur akun break-glass harus sudah diuji sebelum shift. Kontak juga harus diuji (uji kontak mingguan), executive sponsor butuh delegasi tertulis saat cuti, kontak retainer harus siap, dan jadwal harus bisa dibuka saat wiki atau jaringan kantor bermasalah. Lihat bagian 1.5 dan 2.4.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Manajer NOC Bambang Hartono, dalam tiga kalimat, kenapa handover insiden keamanan harus lebih lengkap daripada handover shift NOC yang biasa ia tulis.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Di gangguan jaringan, status tiket biasanya sudah menjelaskan semuanya, tetapi di insiden keamanan sebagian besar pekerjaan ada di kepala orang: hipotesis yang sedang diuji dan alasan setiap keputusan. Ada juga hal yang sengaja belum dilakukan, misalnya server belum di-restart karena memorinya harus diambil dulu, dan kalau itu tidak ditulis, shift berikutnya bisa menghapus bukti atau memberi tahu penyerang terlalu dini. Karena itu handover insiden memisahkan fakta, hipotesis, keputusan beserta alasannya, hal yang sengaja belum dilakukan, dan siapa yang menunggu kabar."

Kesalahan yang sering muncul:
- Hanya menyebut "lebih detail" tanpa menyebut isi yang membedakan (hipotesis, keputusan dan alasannya, hal yang sengaja belum dilakukan).
- Menganggap "detail ada di channel" sudah cukup. Penerima tidak tahu mana fakta dan mana dugaan.
- Melupakan konfirmasi penerima; handover yang hanya dikirim belum tentu diterima.

</details>

**6. Pertanyaan jebakan.** "NIST SP 800-61 r3 sudah tidak membahas IR plan, karena isinya diganti menjadi profil CSF 2.0. Jadi untuk audit, IR plan cukup mengacu ke r2." Benarkah?

<details><summary>Jawaban</summary>

Tidak. R3 memang tidak mengulang daftar delapan elemen plan dari r2, tetapi perencanaan IR tetap ada: ID.IM-04 meminta IR plan ditetapkan, dikomunikasikan, dipelihara, dan diperbaiki dengan prioritas High, RS.MA-01 meminta plan dijalankan bersama pihak ketiga terkait setelah insiden dinyatakan, GV.RR-02 meminta peran dan wewenang IR didokumentasikan, dan section 2.3 dokumen r3 masih memuat elemen kebijakan IR. R2 sudah digantikan r3 sejak April 2025. Daftar r2 tetap berguna dikenali karena masih sering dikutip, tetapi acuan terbarunya r3. Lihat bagian 1.2, 1.7, dan 6.

</details>

**7. Interview question (English).** "You join as an L2 analyst and find that the night shift waits too long before escalating, and incidents lose context at shift change. What would you put in place?"

<details><summary>Sample answer</summary>

"First I'd check whether the problem is authority, contacts, or context, because they need different fixes. For authority, the IR plan should state who can declare an incident and which containment actions the on-call incident commander can order without normal change approval, while business decisions like taking a customer service offline stay with an executive. Then I'd build a RACI with exactly one accountable person per action, and an escalation matrix with concrete triggers such as severity, personal data, privileged accounts, and critical systems, using phone paging and a timeout that moves to the backup after a set number of minutes, calculated back from the severity target. On-call needs a primary and a secondary with tested access, and handovers should be written, separating facts, hypotheses, decisions with their reasons, and things we deliberately haven't done yet, with the receiver confirming. Finally I'd test it cheaply, with weekly contact tests and quarterly access checks, and review the plan after every major incident."

What makes this answer strong: it separates authority, ownership, escalation, readiness, and context instead of treating them as one problem, keeps business decisions with leadership, uses measurable timeouts, and ends with how the fix is tested.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | NIST SP 800-61 Rev. 3: Incident Response Recommendations and Considerations for Cybersecurity Risk Management, A CSF 2.0 Community Profile | https://csrc.nist.gov/pubs/sp/800/61/r3/final (isi dibaca dari PDF https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf) | primer | April 2025; diakses 2026-10-14 | Tinggi. Section 2.2 dan 2.3 (peran, elemen kebijakan, playbook), tabel profil (GV.RR-02, GV.OC-03, ID.IM-01 sampai ID.IM-04, RS.MA, RS.CO-02, RS.CO-03), change log |
| S2 | NIST SP 800-61 Rev. 2: Computer Security Incident Handling Guide | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf | primer | Agustus 2012 (lebih dari 3 tahun, sudah digantikan r3); diakses 2026-10-14 | Tinggi untuk isi r2: elemen kebijakan, plan, dan prosedur (2.3), kebutuhan 24/7, tim paruh waktu, moral on-call, pembagian tanggung jawab dengan outsourcer (2.4) |
| S3 | NCSC UK: Incident management collection, halaman Processes for Cyber Incident Response | https://www.ncsc.gov.uk/collection/incident-management/cyber-incident-response-processes | primer | diakses 2026-10-14 | Tinggi. Isi minimum IR plan, kontak 2 orang dan 2 metode, wewenang didelegasikan dan wewenang di muka, kriteria eskalasi, playbook awal 3 sampai 5 jenis insiden, kanal alternatif. Halaman indeks koleksi: https://www.ncsc.gov.uk/collection/incident-management |
| S4 | Google SRE Book, bab 14: Managing Incidents | https://sre.google/sre-book/managing-incidents/ | sekunder (praktik operasi) | 2017 (lebih dari 3 tahun); diakses 2026-10-14 | Tinggi untuk praktik incident command: pemisahan peran, dokumen status insiden, serah terima komando yang eksplisit, rotasi peran |
| S5 | PagerDuty Incident Response Documentation: Different Roles | https://response.pagerduty.com/before/different_roles/ | sekunder (vendor) | diakses 2026-10-14 | Sedang-tinggi. Peran IC, deputy, scribe, liaison; deputy sebagai cadangan IC |
| S6 | PagerDuty Incident Response Documentation: Being On-Call | https://response.pagerduty.com/oncall/being_oncall/ | sekunder (vendor) | diakses 2026-10-14 | Sedang-tinggi. Prasyarat on-call, timeout eskalasi 5 menit, shift cadangan, handoff akhir shift. Konteksnya tim engineering PagerDuty sendiri |
| S7 | PagerDuty Incident Response Documentation: Incident Commander training | https://response.pagerduty.com/training/incident_commander/ | sekunder (vendor) | diakses 2026-10-14 | Sedang-tinggi. Prosedur serah terima komando, alasan serah terima, pimpinan yang masuk ke call, IC tidak mengerjakan remediasi |
| S8 | PagerDuty Incident Response Documentation: During an Incident | https://response.pagerduty.com/during/during_an_incident/ | sekunder (vendor) | diakses 2026-10-14 | Sedang. Pengumuman peran saat IC baru mengambil alih; dipakai sebagai pendukung S7 |
| S9 | CIO.com: The RACI matrix, your blueprint for project success | https://www.cio.com/article/287088/project-management-what-is-raci-and-how-does-it-improve-clarity.html | sekunder (media) | 2025-03-28; diakses 2026-10-14 | Sedang. Definisi R, A, C, I, aturan satu Accountable, kesalahan umum RACI. Bukan sumber khusus IR |
| S10 | CISA: Federal Government Cybersecurity Incident and Vulnerability Response Playbooks | https://www.cisa.gov/resources-tools/resources/federal-government-cybersecurity-incident-and-vulnerability-response-playbooks | primer | tanggal tidak tercantum di halaman; diakses 2026-10-14 | Sedang untuk Day ini. Hanya halaman ringkasan yang dibaca: mandat EO 14028, scope instansi sipil federal AS |

**Catatan sumber:** angka target waktu, timeout 10 menit dan 5 menit, aturan rotasi, dan seluruh isi PT JAB adalah contoh fiktif, bukan angka dari sumber; satu-satunya angka timeout dari sumber adalah saran 5 menit PagerDuty untuk tim engineering-nya [S6]. Aturan satu Accountable per aktivitas berasal dari panduan RACI umum [S9], bukan dari NIST atau NCSC. Isi PDF playbook CISA tidak dibahas di Day ini; tanggal edisinya perlu dicek di dokumen PDF. Nama kategori CSF 2.0 diambil dari tabel profil di NIST SP 800-61 r3, bukan dari dokumen CSF 2.0 sendiri.
