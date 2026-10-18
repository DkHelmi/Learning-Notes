---
day: 09
title: 'Hunting endpoint dengan Velociraptor: artifact, hunt lintas fleet, VQL, client monitoring, dan kapan beralih dari SIEM'
researched_on: 2026-10-18
versions_checked: 'Velociraptor 0.77.3 (5 Okt 2026, rilis terbaru di GitHub); referensi artifact Velociraptor (Windows.Sysinternals.Autoruns, Windows.Sys.StartupItems, Windows.System.TaskScheduler, Windows.Search.FileFinder, Windows.Forensics.Prefetch, Windows.System.DNSCache, Windows.Network.NetstatEnriched, Windows.Remediation.Quarantine, Windows.Events.ProcessCreation, Windows.Sigma.EventLogs); dokumentasi Velociraptor (overview, deployment, hunting, client monitoring, resource limits, offline collections, VQL fundamentals); Velociraptor Sigma project; MITRE ATT&CK v20 (T1053.005, T1574, T1574.001, T1547.001)'
---

# Day 09: Hunting endpoint dengan Velociraptor (artifact, hunt lintas fleet, VQL, client monitoring, dan offline collector)

Cakupan: konsep client, server, artifact, hunt, notebook, dan client monitoring Velociraptor, risiko dan beban memasang client ke seluruh fleet, cara menjalankan hunt lintas ratusan host dengan stacking di notebook VQL, cara menangani host yang offline atau berada di luar kantor, offline collector, serta kapan hunt harus beralih dari SIEM ke endpoint dan kapan SIEM sudah cukup.

## Ide inti

SIEM hanya tahu apa yang pernah dikirim kepadanya. Isi registry, file XML scheduled task, prefetch, file di folder profil pengguna, dan DLL yang duduk di samping sebuah executable jarang dikirim sebagai log, dan di host tanpa Sysmon atau EDR bahkan peristiwa pembuatannya pun tidak tercatat. Velociraptor menutup celah itu dengan cara yang berbeda dari SIEM: alih-alih menunggu log datang, ia mengajukan pertanyaan yang sama (sebuah artifact) ke setiap endpoint, lalu mengumpulkan jawabannya di satu tempat untuk ditumpuk dan dibandingkan. Hunt endpoint karena itu adalah stacking atas keadaan mesin saat ini, bukan atas riwayat log. Kekuatan ini datang dengan dua harga yang harus ditulis di setiap laporan: hanya host yang terhubung yang menjawab, dan server yang bisa bertanya ke semua host juga bisa menyuruh semua host melakukan apa saja.

Kamu sudah mengenal pola ini dari ISP. CPE pelanggan yang memakai TR-069 menghubungi ACS secara berkala; ACS tidak membuka koneksi ke CPE, tetapi begitu CPE memanggil pulang, ACS bisa membaca parameter atau memberi tugas. Membaca parameter yang sama dari ribuan CPE lalu mencari yang menyimpang adalah hunt. Syslog dan NetFlow yang sudah tersimpan di kolektor adalah SIEM. Batas analoginya ada tiga. Pertama, CPE yang mati atau di luar jangkauan tidak menjawab sampai ia memanggil pulang lagi, jadi hasil hunt selalu hanya mewakili host yang terhubung selama hunt aktif. Kedua, jawaban endpoint adalah keadaan sekarang, sehingga sesuatu yang sudah dihapus tidak terlihat kecuali meninggalkan artefak lain. Ketiga, ACS hanya mengatur konfigurasi, sedangkan server Velociraptor bisa membaca file apa pun dan menjalankan program di setiap endpoint; ia harus diperlakukan setara domain controller, bukan seperti server monitoring biasa.

```
   SIEM (log yang sudah dikirim)              Velociraptor (keadaan endpoint sekarang)
   ------------------------------              ----------------------------------------
   event -> forwarder -> index                 analyst memilih artifact + parameter
          |                                              |
   search historis, korelasi lintas sumber     hunt: kondisi (label, OS), batas sumber daya,
          |                                          expiry (default 1 minggu)
   "host X aneh"  ------- pivot ke ------->              |
                                               client yang online menjalankan, mengirim hasil
                                               client offline menjalankan saat kembali terhubung
                                                         |
                                               notebook hunt: stacking (GROUP BY dua tahap)
                                                         |
                                               baris langka -> pengumpulan terarah (read-only)
                                                         |
               <------- pivot balik ---------  domain/IP baru -> cek di SIEM (dns, vpn, proxy)
                                                         |
                       hasil + cakupan (berapa host menjawab, berapa tidak) -> handover
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan, kantor pusat dan data center di Jakarta, serta POP regional di Bandung, Surabaya, dan Medan. SOC PT JAB memakai Splunk Enterprise dengan Enterprise Security (ES); Sysmon hanya terpasang di 61 server Windows dan 153 workstation Jakarta di OU `Workstations-EDR`, sehingga 229 dari 382 workstation tidak punya Sysmon. Microsoft Defender for Endpoint (MDE) ada di server dan workstation Jakarta serta Bandung, tetapi tidak di 23 workstation POP Surabaya dan Medan. Karyawan di luar kantor memakai VPN GlobalProtect dengan split tunnel. Sejak 1 Februari 2027 kamu (analyst L2) memegang Program hunt PT JAB setiap Selasa dan Kamis. Senin 2027-02-22, SOC lead Dimas Prasetyo menyetujui server Velociraptor permanen `jkt-velo02` (`10.20.1.31`, jaringan manajemen) khusus untuk hunting, dan client dipasang ke workstation serta server Windows lewat paket software dan GPO pada 22 sampai 24 Februari. Alasannya satu: menjangkau 229 workstation tanpa Sysmon sambil menunggu rollout Sysmon. Kamis 2027-02-25 pukul 07:50, Dimas menulis kepadamu:

> "Velo sudah jalan dan client-nya terpasang sejak Senin. Minggu depan aku harus lapor ke Pak Hendra, dan Pak Agung juga sudah tanya-tanya, jadi tolong bantu jawab. Apa yang bisa dilihat Velociraptor yang tidak bisa kita lihat di Splunk? Pak Agung khawatir soal risikonya: agent yang bisa menjalankan apa saja di semua laptop dan server, apa tidak bahaya? Bagaimana menjalankan hunt ke ratusan host tanpa bikin laptop orang lambat dan server penuh? Untuk persistence, artifact mana yang dipakai? Bagaimana dengan laptop yang jarang online, terutama sales POP yang jarang ke kantor? Velo katanya bisa memantau real-time juga; perlu dinyalakan sekarang? Terakhir, kapan cukup pakai Splunk saja, supaya anak-anak tidak membuka Velo untuk semua hal. Kalau bisa, hari ini jalankan dua hunt persistence pertama."

Pesan itu memuat tujuh pertanyaan:

1. Apa yang bisa dilihat Velociraptor yang tidak terlihat di SIEM?
2. Apa risiko memasang client ke seluruh fleet, dan bagaimana mengendalikannya?
3. Bagaimana menjalankan hunt lintas fleet tanpa membebani endpoint dan server?
4. Artifact mana yang dipakai untuk persistence?
5. Bagaimana dengan host yang offline dan laptop di luar kantor?
6. Perlukah client monitoring real-time dinyalakan sekarang?
7. Kapan cukup memakai SIEM?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.3, pertanyaan 3 di bagian 1.4 dan 1.5 (dengan VQL notebook di bagian 1.6), pertanyaan 4 di bagian 1.2, pertanyaan 5 di bagian 1.7, pertanyaan 6 di bagian 1.8, dan pertanyaan 7 di bagian 1.9. Bagian 2 berisi dua hunt hari Kamis itu: `HUNT-2027-012` (stacking autoruns, hasil jinak) dan `HUNT-2027-013` (scheduled task, yang menemukan persistence aktif di laptop sales POP Surabaya), lalu pengumpulan terarah, eskalasi ke IR, dan jawaban untuk Dimas.

**Kapan relevan:** saat pertanyaan hunt menyangkut artefak yang tidak dikirim ke SIEM (autostart, file task, file di disk, prefetch, DLL di folder aplikasi); saat host target tidak punya Sysmon atau EDR; saat temuan SIEM perlu diverifikasi di mesinnya; dan saat butuh jawaban dangkal dari banyak host sekaligus.
**Kapan bukan jawaban:** saat pertanyaannya historis atau lintas sumber dan datanya sudah ada di SIEM (Splunk lebih cepat dan tidak menyentuh endpoint); saat host target tidak punya client atau tidak pernah terhubung selama hunt aktif (hasilnya kosong, bukan bersih); dan saat insiden sudah dinyatakan, karena pengumpulan dan tindakan di host lalu menjadi keputusan IR, walaupun alatnya sama.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (threat hunting, hipotesis, stacking, long tail, baseline, normalisasi, handover, hunt abstract, backlog) tidak diulang. Tabel ini hanya memuat istilah baru di Day ini; kolom kanan memetakannya ke pengalaman NOC, ISP, dan SOC.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Velociraptor | Platform open-source untuk endpoint monitoring, DFIR, dan respons, dengan client di endpoint dan server pusat | ACS TR-069 yang bisa membaca parameter dan memberi tugas ke semua CPE |
| Client (agent) | Service di endpoint yang menjaga koneksi persisten ke server dan menunggu tugas | CPE yang memanggil pulang ke ACS |
| Server dan frontend | Komponen pusat; frontend menerima koneksi client, GUI dipakai analyst | ACS dan portal operatornya |
| VQL | Velociraptor Query Language, bahasa query berbentuk `SELECT ... FROM plugin() WHERE ...` | Bahasa template perintah di tool otomasi jaringan |
| Artifact | Query VQL yang dikemas dengan nama, deskripsi, parameter, dan source | Template perintah show yang disimpan dengan parameter |
| Source | Bagian bernama di dalam artifact; hasil dibaca dengan `source(artifact="Nama/Source")` | Satu bagian keluaran `show tech` |
| Collection (flow) | Satu kali menjalankan artifact di satu client | Satu kali menjalankan perintah ke satu perangkat |
| Hunt | Menjalankan satu artifact di banyak client yang memenuhi kondisi selama hunt aktif | Menjalankan perintah show yang sama ke semua CPE lalu membandingkan keluarannya |
| Label | Penanda pada client untuk menarget atau mengecualikan hunt | Group perangkat di NMS (per POP, per model) |
| Expiry | Batas waktu hunt; client yang terhubung sebelum batas itu ikut, sisanya tidak | Jendela maintenance: yang online di jendela itu ikut |
| Notebook | Lembar kerja VQL untuk mengolah hasil collection atau hunt | Spreadsheet kerja untuk menggabungkan keluaran semua perangkat |
| Resource limits | Batas waktu, baris, upload, CPU, IOPS, dan laju operasi per collection | Rate limit perintah ke control plane supaya polling tidak menaikkan CPU |
| `EXECVE` | Izin untuk menjalankan program eksternal di endpoint lewat plugin `execve()` | Privilege level 15 di router |
| Client monitoring | Artifact bertipe `CLIENT_EVENT` yang berjalan terus dan mengalirkan event ke server | Streaming telemetry atau SNMP trap, dibanding polling sekali |
| ETW / eBPF | Sumber event live di Windows (Event Tracing for Windows) dan Linux (extended Berkeley Packet Filter) | Debug counter langsung dari ASIC, bukan dari syslog |
| Sigma | Format rule deteksi generik berbasis YAML yang bisa dipakai di banyak alat | Template rule alarm yang bisa diimpor ke NMS merek mana pun |
| Offline collector | Binary Velociraptor mandiri yang membawa artifact terpilih, dijalankan di host tanpa client, dan menghasilkan file ZIP | Teknisi membawa laptop konsol ke POP yang link manajemennya putus, mengambil `show tech`, lalu membawanya pulang |
| Split tunnel | VPN yang hanya membawa trafik ke jaringan kantor; trafik internet keluar langsung dari koneksi rumah | Pelanggan dua jalur: trafik ke kantor lewat tunnel, internet lewat ISP lokal |
| DLL side-loading | Program sah yang memuat DLL berbahaya bernama sama dari foldernya sendiri | Perangkat sah yang memuat file konfigurasi dari folder kerja sebelum folder bawaan |

### 1.1 Log vs keadaan endpoint: apa yang dilihat Velociraptor

Pertanyaan pertama Dimas lahir dari kebiasaan yang wajar: selama ini semua jawaban SOC PT JAB datang dari Splunk. Di 229 workstation tanpa Sysmon, Splunk tidak tahu proses apa yang dibuat, DLL apa yang dimuat, atau task apa yang terdaftar. Yang tersisa hanya Security log, dan di luar OU `Workstations-EDR` audit pembuatan scheduled task (Event ID 4698) pun tidak aktif karena GPO `JAB-WS-Audit` hanya ditautkan ke OU itu.

Velociraptor adalah platform open-source untuk endpoint monitoring, DFIR, dan respons [S2]. Konsep intinya ada tujuh, dan tabel berikut merangkumnya; baca kolom kanan sebagai satu kalimat model mental per konsep.

| Konsep | Arti | Model mental |
|---|---|---|
| Client (agent) | Dipasang sebagai service di endpoint, menjaga koneksi persisten ke server agar bisa diberi tugas [S2] | Endpoint yang siap ditanya |
| Server | On-prem atau cloud; tempat investigator memberi tugas dan meninjau hasil [S2] | Tempat bertanya dan menyimpan jawaban |
| VQL (Velociraptor Query Language) | Bahasa query untuk membangun artifact, membuat aturan monitoring, dan otomasi [S2] | Cara merumuskan pertanyaan |
| Artifact | Koleksi berbasis VQL yang mengumpulkan data spesifik dari endpoint [S2] | Pertanyaan yang bisa diulang |
| Hunt | Menjalankan satu artifact di banyak endpoint untuk menemukan aset yang terkompromi [S2] | Pertanyaan ke seluruh fleet |
| Client monitoring | Deteksi real-time dari sumber event live (ETW di Windows, eBPF di Linux), bisa menerapkan rule Sigma [S2] | Pertanyaan yang terus dijawab |
| Notebook | Lingkungan interaktif untuk analisis kolaboratif [S2] | Tempat menganalisis jawaban |

Model mentalnya: artifact adalah pertanyaan yang bisa diajukan ke endpoint; hunt mengajukan pertanyaan itu ke seluruh fleet; notebook adalah tempat menganalisis jawabannya.

Bedanya dengan SIEM ada di arah aliran data. Di SIEM, endpoint menentukan apa yang dikirim (lewat audit policy, konfigurasi Sysmon, dan forwarder), lalu analyst bertanya ke data yang sudah tersimpan. Di Velociraptor, analyst menentukan pertanyaan, dan endpoint menjawab dari keadaan mesin saat itu: file di disk, registry, file task, prefetch, cache DNS, koneksi jaringan yang sedang terbuka. Karena itu Velociraptor melihat hal yang tidak pernah di-log, termasuk di host tanpa Sysmon, selama ada artefak yang tersisa di mesin. Dokumentasinya juga menekankan bahwa query dijalankan di endpoint dan hanya hasilnya yang dikirim, yang membuat triage bisa diskalakan ke seluruh lingkungan [S2].

Di PT JAB, jawaban untuk pertanyaan pertama Dimas cukup satu kalimat: Splunk tahu apa yang terjadi dan dikirim, Velociraptor tahu apa yang ada di mesin sekarang, termasuk di 229 workstation yang tidak pernah mengirim Sysmon.

### 1.2 Artifact: pertanyaan yang bisa diulang, dan artifact untuk persistence

Pertanyaan keempat Dimas ("artifact mana untuk persistence?") menuntut tahu dulu apa itu artifact dan bagaimana memilihnya, karena nama artifact berubah antar versi dan nama yang salah adalah penyebab paling umum hunt pertama gagal.

Artifact adalah query VQL yang dikemas dengan nama, deskripsi, parameter, dan sumber. Velociraptor membawa ratusan artifact bawaan, dikelompokkan per sistem (Windows, Linux, generic) dan per jenis (Collection untuk sekali ambil, Event untuk monitoring). Contoh kategori artifact bawaan:

- Proses dan eksekusi: daftar proses, prefetch, Amcache, Shimcache.
- Persistence: autoruns, scheduled task, service, Run key, WMI subscription.
- Jaringan: koneksi, DNS cache.
- File: pencarian file, hash, metadata NTFS.

Untuk hunting, kamu jarang menulis artifact dari nol; kamu memilih artifact bawaan, mengatur parameternya, dan menjalankannya sebagai hunt. Nama artifact bisa berubah antar versi, jadi cek nama persis di daftar artifact UI server sebelum membuat hunt. Nama yang dipakai di Day ini sudah dicocokkan dengan referensi artifact 0.77.x: `Windows.Sysinternals.Autoruns`, `Windows.Sys.StartupItems`, `Windows.System.TaskScheduler`, `Windows.Search.FileFinder`, `Windows.Forensics.Prefetch`, `Windows.Forensics.Amcache`, `Windows.Network.NetstatEnriched`, `Windows.Persistence.PermanentWMIEvents`, `Windows.Events.ProcessCreation`, dan `Windows.Sigma.EventLogs`. Nama `Windows.Sys.Autoruns` tidak ada di referensi artifact saat ini.

Untuk persistence, tiga artifact menjadi pilihan utama. Tabel berikut membandingkannya; baca kolom "Kelemahan" sebelum memilih, karena di sanalah perbedaan bebannya.

| Artifact | Cara kerja | Cakupan | Kelemahan |
|---|---|---|---|
| `Windows.Sysinternals.Autoruns` [S4] | Mengambil `autorunsc.exe`/`autorunsc64.exe` dari server lewat `Generic.Utils.FetchBinary`, menjalankannya dengan keluaran CSV dan hash, lalu mem-parse CSV-nya | Paling luas: logon, service dan driver, scheduled task, WMI, Winlogon, image hijack, AppInit, Known DLLs, LSA provider, dan lainnya, dipilih lewat centang kategori | Butuh izin `EXECVE`; binary harus tersedia di server; proses eksternal tidak ikut dibatasi CPU limit (bagian 1.5); nama kolom mengikuti header CSV `autorunsc` |
| `Windows.Sys.StartupItems` [S5] | Membaca Run/RunOnce key (HKLM dan HKU, termasuk WOW6432Node dan Policies\Explorer\Run), status `StartupApproved`, dan folder Startup per user dan ProgramData | Sempit: Run key dan folder Startup | Tidak melihat service, task, atau WMI |
| `Windows.System.TaskScheduler` [S6] | Meng-glob file XML definisi task di `C:/Windows/System32/Tasks/**` dan mem-parse-nya | Semua task yang terdaftar sebagai file, beserta aksi, akun, dan waktu registrasi | Hanya scheduled task; task tersembunyi yang dimanipulasi lewat registry perlu diuji terpisah (bagian 6) |

Pilihan di PT JAB: autoruns untuk gambaran luas, TaskScheduler untuk scheduled task karena parsing XML-nya memberi kolom yang lebih kaya (akun, waktu registrasi, tanda tangan binary) dan bebannya ringan. Untuk host yang tidak boleh dijalankan binary eksternal, StartupItems adalah cadangan ringan.

### 1.3 Risiko memasang client ke seluruh fleet

Pertanyaan kedua datang dari Agung Prabowo, Lead Infrastruktur: agent yang bisa menjalankan apa saja di 443 host Windows, apa tidak berbahaya? Pertanyaannya tepat, dan jawabannya bukan "aman", tetapi "risikonya ini, dan dikendalikan dengan cara ini".

Risiko pertama adalah kekuasaan server. Model ACL Velociraptor membedakan peran reader, analyst, investigator, artifact_writer, dan administrator [S17]. Analyst hanya membaca dan mengolah hasil; investigator bisa memulai collection dan hunt; artifact_writer bisa membuat atau mengubah artifact sisi client, dan dokumentasinya menyamakan peran ini dengan domain admin di endpoint karena artifact buatan sendiri bisa menjalankan apa saja; administrator bisa menjalankan VQL apa pun di server, yang setara akses shell server [S17]. Plugin `execve()` butuh izin `EXECVE`, dan artifact yang membutuhkannya tidak bisa dijadwalkan oleh pengguna tanpa izin itu [S17]. Tulisan ACL itu berasal dari 2020; cek cara memberi izin per pengguna di versi-mu sebelum menyusun peran.

Risiko kedua adalah kerentanan server. Rilis 0.77.3 adalah rilis perbaikan yang menutup beberapa CVE, dan setiap halaman dokumentasi saat ini menyarankan pembaruan ke versi itu [S1][S2]. Server yang tertinggal versi dan bisa dijangkau dari banyak segmen adalah target yang menarik.

Risiko ketiga adalah beban dan data. Collection yang mengunggah file besar dari ratusan host bisa memenuhi disk server dengan cepat; dokumentasi hunt memberi contoh file 100 MB dari 10.000 mesin yang melebihi 1 TB [S12]. Beban di endpoint dibahas di bagian 1.5.

Risiko keempat adalah privasi. Client bisa membaca file di folder profil pengguna, termasuk dokumen pribadi. PT JAB memegang data pribadi pelanggan, sehingga DPO Agus Setiawan perlu tahu apa yang dikumpulkan dan kapan isi file boleh diunggah.

Kendali yang disepakati Dimas dan Agung untuk `jkt-velo02`, dirangkum dalam tabel berikut. Baca kolom "Risiko yang ditekan" untuk mencocokkan setiap kendali dengan risikonya.

| Kendali | Isi | Risiko yang ditekan |
|---|---|---|
| Server tier-0 | `jkt-velo02` di jaringan manajemen, diperlakukan setara domain controller; patch mengikuti rilis keamanan Velociraptor | Kekuasaan server, kerentanan |
| Jangkauan jaringan | Frontend port 8000 hanya terbuka dari subnet kantor, POP, dan pool VPN; GUI hanya dari subnet SOC | Kerentanan, akses GUI |
| Peran | Dimas administrator; kamu dan Rudi Hartanto investigator dengan izin `EXECVE`; Sari Kusuma analyst; tidak ada artifact_writer selain administrator | Kekuasaan server |
| Default hunt | Metadata dan hash saja; upload isi file hanya untuk collection terarah dengan tiket dan dicatat di laporan | Privasi, data |
| Batas sumber daya | Timeout, `max_rows`, dan `max_upload_bytes` diisi di setiap hunt; hunt berat diuji di label canary dulu | Beban, data |

**Batas kendali:** resource limits ditegakkan oleh client pada dirinya sendiri dan tidak divalidasi server, sehingga client yang sudah dikuasai penyerang bisa mengabaikannya [S14]. Batas sumber daya melindungi pengguna dari hunt yang ceroboh, bukan melindungi server dari endpoint yang sudah dikompromikan.

### 1.4 Hunt lintas fleet: alur, kondisi, dan expiry

Pertanyaan ketiga Dimas punya dua sisi: bagaimana hunt sampai ke ratusan host, dan bagaimana caranya tidak menyiksa host itu. Sisi pertama dijawab di sini.

Hunt menjalankan satu artifact di banyak endpoint sekaligus [S2]. Alurnya:

1. Pilih artifact (misalnya scheduled task atau autoruns).
2. Atur parameter dan kondisi (OS, label client, rentang).
3. Jalankan hunt; client yang online mengeksekusi dan mengirim hasil; yang offline mengeksekusi saat kembali online.
4. Tinjau hasil gabungan di notebook: stacking, filter, dan pivot (Day 05).

Beberapa perilaku hunt yang menentukan cara membaca hasilnya [S12]:

- Hunt dibuat dalam keadaan `Paused` dan baru berjalan setelah di-Start. Ini memberi kesempatan memeriksa parameter sebelum menyentuh fleet.
- Hunt manager menjadwalkan collection ke setiap client yang memenuhi kondisi dan memastikan satu client tidak menerima hunt yang sama dua kali.
- Hunt bisa ditarget ke label tertentu atau mengecualikan client berlabel tertentu. Memberi label pada client akan menjadwalkan hunt yang cocok untuknya, sehingga label bisa dipakai untuk menambah host secara bertahap.
- Hunt tidak "selesai", melainkan kedaluwarsa. Default expiry satu minggu; sampai saat itu, client yang baru terhubung dan memenuhi kondisi tetap menerimanya.
- Setiap hunt punya notebook untuk mengolah hasil dengan VQL; fungsi `hunt_results()` membaca hasil hunt lintas client.

Hunt adalah padanan endpoint dari stacking SIEM: alih-alih menumpuk log yang sudah dikirim, kamu menumpuk artefak live dari tiap mesin. Menumpuk hasil autoruns dari ratusan host untuk menemukan entri yang hanya ada di satu host adalah hunting klasik yang sulit dilakukan hanya dengan log.

Konsekuensi untuk laporan: karena hunt kedaluwarsa dan bukan selesai, angka cakupan harus dibekukan pada satu jam tertentu ("379 dari 443 host menjawab sampai Kamis 16:00"). Hasil yang datang setelah laporan ditulis dicatat sebagai tambahan, bukan diam-diam dimasukkan.

### 1.5 Menjaga beban endpoint dan server

Sisi kedua pertanyaan Dimas: laptop sales tidak boleh terasa lambat hanya karena SOC sedang hunting, dan disk server tidak boleh penuh di minggu pertama.

Velociraptor menyediakan resource limits per collection; di hunt, nilainya diisi di GUI saat membuat hunt dan berlaku untuk setiap client [S14]. Tabel berikut memuat batas yang perlu kamu isi; baca kolom "Perilaku saat tercapai", karena beberapa batas membatalkan collection dan beberapa hanya memperlambat.

| Batas | Default | Perilaku saat tercapai |
|---|---|---|
| `timeout` | 600 detik (offline collector tanpa timeout) | Collection dibatalkan |
| `max_rows` | tidak disebut | Collection dibatalkan; tidak berlaku untuk artifact server |
| `max_upload_bytes` | tidak disebut | Collection dibatalkan |
| `cpu_limit` | tidak ada batas kecuali diisi | Query dijeda saat rata-rata CPU melewati ambang, lanjut saat turun |
| `iops_limit` | tidak disebut | I/O diperlambat; terutama berguna untuk scan YARA besar |
| `ops_per_second` | tidak disebut | Laju operasi VQL dibatasi; diisi di level collection |
| `progress_timeout` | tidak diisi | Query yang tidak mengeluarkan baris dalam waktu itu dihentikan |
| `max_batch_rows`, `max_batch_wait` | 1.000 baris, 100 detik | Hanya mengatur ukuran dan jeda pengiriman, tidak membatalkan |

Sumber: dokumentasi Limiting resource usage [S14]. Urutan prioritas nilainya: default bawaan, lalu `resources` di definisi artifact, lalu override per artifact, lalu nilai di level collection atau hunt yang paling menentukan [S14].

Tiga jebakan dari dokumentasi yang sama [S14]:

- CPU limit dan IOPS limit tidak berlaku untuk program eksternal yang dijalankan lewat `execve()`. Untuk `Windows.Sysinternals.Autoruns`, proses `autorunsc` tetap memakai CPU sebanyak yang ia mau; yang bisa dikendalikan hanya timeout dan jumlah host yang menjalankannya bersamaan.
- CPU limit yang terlalu rendah bisa membuat query menunggu lama, dan dokumentasi tidak menyarankan CPU limit global.
- `max_rows` membatalkan seluruh collection, sedangkan `max_batch_rows` hanya mengatur ukuran paket yang dikirim. Keduanya mudah tertukar.

Selain angka, beban diatur dengan urutan. Pola yang dipakai PT JAB:

1. **Canary dulu.** Jalankan hunt ke label `velo-canary` (25 client: 5 server dan 20 workstation Jakarta milik tim IT dan SOC). Ukur durasi median dan maksimum, ukuran hasil, dan keluhan pengguna.
2. **Baru seluruh fleet**, dengan hunt kedua yang mengecualikan label canary supaya host canary tidak menjalankan dua kali.
3. **Kecilkan keluaran.** Pilih artifact yang mengembalikan sedikit baris per host, bukan file mentah untuk di-parse belakangan; dokumentasi hunt menyarankan hal yang sama [S12]. Hash dan metadata dikirim, isi file tidak.
4. **Pemindaian isi file dibatasi laju.** Dokumentasi `Windows.Search.FileFinder` menyarankan rate limit sekitar 20-50 ops per detik bila memindai isi file [S8].

### 1.6 VQL secukupnya untuk notebook

Hasil hunt tidak dibaca baris per baris; ia ditumpuk di notebook. Untuk itu kamu perlu cukup VQL untuk membaca artifact bawaan dan menulis query stacking, bukan untuk menulis artifact dari nol.

VQL mirip SQL dengan plugin. Bentuk dasarnya:

```
SELECT <kolom> FROM <plugin>(args) WHERE <kondisi>
```

- Plugin menghasilkan baris (misalnya `pslist()`, `glob()`, membaca registry).
- Fungsi memproses nilai (hash, parsing waktu).
- Artifact membungkus satu atau lebih query VQL dengan metadata.

Lima perilaku VQL yang dipakai di bagian 2 [S3]:

- `GROUP BY` membagi baris ke dalam bin per nilai, dan fungsi agregat seperti `count()`, `sum()`, dan `enumerate()` menyimpan state terpisah untuk tiap bin. Hanya pilih kolom yang ikut di-`GROUP BY` atau hasil fungsi agregat; kolom lain di bin yang sama bisa berisi nilai apa saja, dan urutan baris di dalam bin tidak boleh diandalkan.
- VQL tidak punya fungsi distinct count. Untuk menghitung jumlah host per entri, rapatkan dulu ke satu baris per pasangan host dan entri, lalu hitung per entri (dua tahap).
- `LET x = SELECT ...` menyimpan query yang dievaluasi saat dirujuk; `LET x <= SELECT ...` mengevaluasinya sekali dan menyimpan hasilnya di memori.
- `=~` adalah operator regex (sintaks RE2 milik Go, tanpa lookaround dan backreference). Pencocokannya tidak peka huruf besar/kecil secara default; pakai `(?-i)` bila perlu peka huruf. Tidak ada operator `!~`; pakai `NOT`. Untuk pola regex, string mentah `'''...'''` dianjurkan agar backslash tidak perlu di-escape berlapis.
- Nama kolom yang mengandung spasi ditulis dengan backtick, misalnya `` `Image Path` ``.

Untuk hunting, cukup bisa membaca VQL artifact bawaan dan menyesuaikan `WHERE` atau parameter. Menulis VQL kompleks dari nol adalah keterampilan lanjutan; mulai dari artifact yang ada. Cek nama plugin dan fungsi VQL persis di dokumentasi versi lab.

### 1.7 Host offline dan laptop di luar kantor

Pertanyaan kelima Dimas menyentuh kelemahan paling nyata dari pendekatan ini di PT JAB: laptop sales, terutama di POP, jarang berada di kantor, dan sebagian belum pernah terhubung sejak paket client dibagikan.

Client selalu memulai koneksi ke server, bukan sebaliknya: client dikonfigurasi dengan URL server (misalnya `https://...:8000/`) lalu menjaga koneksi persisten untuk menunggu tugas [S16]. Di PT JAB, URL itu menunjuk ke `jkt-velo02` (`10.20.1.31`) di jaringan manajemen. Tabel berikut menunjukkan kapan sebuah laptop bisa menjangkaunya; baca kolom kanan sebagai konsekuensi untuk hunt.

| Lokasi laptop | Jalur ke `jkt-velo02` | Konsekuensi |
|---|---|---|
| Di kantor Jakarta, Bandung, atau POP | Jaringan internal | Menjawab hunt segera |
| Di luar kantor, VPN GlobalProtect tersambung | Lewat tunnel, karena subnet internal dibawa split tunnel | Menjawab hunt selama VPN tersambung |
| Di luar kantor, VPN tidak tersambung | Tidak ada | Tidak menjawab; hunt menunggu sampai expiry |

Split tunnel membawa dua konsekuensi sekaligus. Yang pertama di atas: client hanya terhubung saat VPN tersambung. Yang kedua lebih penting untuk hunting: trafik internet laptop di luar kantor tidak lewat proxy dan resolver PT JAB, sehingga apa pun yang diunduh atau dihubungi laptop itu dari rumah tidak pernah ada di `index=proxy` maupun `index=dns`. Untuk laptop seperti ini, keadaan endpoint adalah satu-satunya sumber yang tersisa, dan Velociraptor hanya bisa membacanya saat laptop tersambung.

Opsi membuka frontend ke internet (lewat DMZ) supaya laptop bisa terhubung tanpa VPN dibahas dan ditolak untuk sekarang: server tier-0 yang menghadap internet memperluas permukaan serangan, dan rilis keamanan Velociraptor tahun ini menunjukkan bahwa server memang punya kerentanan [S1]. Keputusan ini dicatat sebagai risiko yang diterima: cakupan laptop di luar kantor bergantung pada VPN.

Tiga mekanisme menutup sebagian celah:

- **Expiry hunt.** Hunt yang aktif seminggu memberi waktu bagi laptop yang hanya sesekali tersambung [S12]. Untuk hunt penting, expiry bisa diperpanjang, dengan konsekuensi laporan harus menunggu atau ditulis bertahap.
- **Buffer lokal untuk monitoring.** Hasil client monitoring dari client yang offline disimpan di buffer lokal (`Client.local_buffer`) dan dikirim saat terhubung lagi [S13]. Konfigurasi default menyebut buffer 50 MB di memori dan 1 GB di disk [S16]. Ini berlaku untuk event, bukan untuk hunt yang belum diterima.
- **Offline collector.** Velociraptor bisa membuat offline collector: satu paket mandiri yang dijalankan di host tanpa agent, mengumpulkan artifact, dan menghasilkan file hasil untuk dianalisis di server. Berguna untuk host yang tidak bisa dipasangi agent atau untuk triage cepat. Untuk hunting lintas fleet, agent persisten lebih cocok; collector lebih ke forensik ad hoc di satu host.

Detail offline collector yang perlu diketahui sebelum memakainya [S15]:

- Collector adalah binary Velociraptor penuh dengan konfigurasi dan artifact terpilih tertanam di dalamnya; tool pihak ketiga yang dibutuhkan bisa ikut dibundel.
- Hasilnya berupa container ZIP. Enkripsi yang dianjurkan adalah X.509: password acak dienkripsi dengan sertifikat server, sehingga server bisa mendekripsinya saat impor. Opsi password tetap tidak dianjurkan karena password tertanam di collector dan mudah diambil.
- Container bisa diunggah otomatis ke penyimpanan jaringan atau cloud, lalu salinan lokalnya dihapus. Saat diimpor, server membuat record client dan collection, sehingga hasilnya bisa diolah seperti data client lain.
- Collector cocok bila server tidak bisa dijangkau, pemasangan software ditolak, atau orang yang menjalankannya bukan ahli. Ia tidak cocok bila endpoint bisa menjangkau server (client online lebih sederhana) atau bila yang dibutuhkan hanya menyalin file mentah.
- Collection biasanya sekali jalan, jadi daftar artifact harus direncanakan matang; artifact dijalankan dengan concurrency default 2 dan urutan yang praktis acak.

Untuk PT JAB, offline collector adalah rencana bagi laptop POP yang tidak tersambung dalam satu minggu: dikirim lewat manajer POP dan dijalankan saat laptop dibawa ke kantor, dengan hasil diunggah ke share di jaringan manajemen.

### 1.8 Client monitoring dan Sigma: kapan aliran lebih tepat dari snapshot

Pertanyaan keenam Dimas ("perlu dinyalakan sekarang?") membutuhkan pembedaan yang jelas antara hunt dan monitoring, karena keduanya memakai server yang sama tetapi menjawab pertanyaan berbeda.

Client monitoring memakai artifact tipe Event yang menyadap sumber live: ETW di Windows, eBPF di Linux [S2]. Ia bisa menerapkan rule Sigma langsung di endpoint [S2]. Sigma adalah format rule deteksi generik berbasis YAML: blok `logsource` menyebut jenis log (misalnya `category: process_creation`, `product: windows`) dan blok `detection` berisi pola field (misalnya `Image|endswith: '\\mshta.exe'`) serta `condition`. Velociraptor memetakan `logsource` dan nama field Sigma ke sumber datanya sendiri, sehingga rule yang sama bisa dievaluasi di endpoint tanpa dikonversi ke bahasa query SIEM. Bedanya dari hunt: hunt adalah snapshot sekali ambil; client monitoring adalah aliran berkelanjutan. Untuk hunting, monitoring berguna menangkap perilaku yang hanya muncul sesaat (proses berumur pendek, koneksi singkat) yang mungkin terlewat snapshot.

Cara kerjanya di server [S13]:

- Artifact monitoring dipilih per client lewat `Client Events` dan tombol untuk memperbarui tabel monitoring; hanya artifact bertipe `CLIENT_EVENT` yang muncul.
- Monitoring bisa berlaku untuk semua client atau untuk label tertentu. Keanggotaan label dinamis, jadi menambah atau mencabut label langsung mengubah query monitoring client itu.
- Client menyimpan query monitoring di file writeback-nya sehingga berjalan sejak startup. Baris dikumpulkan di memori lalu dikirim, secara default sampai sekitar 120 detik, sehingga event bisa terlambat sekitar dua menit.
- Secara default server hanya menyimpan event dan tidak bertindak atasnya; reaksi otomatis butuh query event di sisi server.

Sigma di Velociraptor bekerja di dalam "model": setiap model mendefinisikan log source dan pemetaan field yang tersedia, dan sebuah rule hanya bisa berjalan di model yang menyediakannya [S18]. `Windows.Sigma.Base` memeriksa file `.evtx` yang sudah ada di endpoint (triage); model real-time seperti `Windows.Sigma.BaseEvents`, `Windows.ETW.Base`, dan `Linux.Sigma.EBPF` membaca event live [S18]. Proyek Velociraptor Sigma menerbitkan artifact siap pakai, antara lain `Windows.Sigma.Triage` untuk triage serta `Windows.ETW.Monitoring`, `Windows.Hayabusa.Monitoring`, dan `Linux.EBPF.Monitoring` untuk monitoring real-time [S19]. Pemisahan triage dan monitoring itu terbaca dari nama artifact-nya; cek deskripsi tiap artifact di server-mu sebelum memasangnya.

Pertimbangan untuk PT JAB: monitoring yang mengevaluasi rule `process_creation` atas log Sysmon tidak berguna di host tanpa Sysmon, karena sumbernya tidak ada. Untuk 229 workstation itu, sumber process creation yang tersedia adalah ETW atau WMI (bagian 2.9). Karena itu jawabannya untuk Dimas: belum dinyalakan ke seluruh fleet minggu ini; usulan pilot ditulis di bagian 2.9.

### 1.9 Velociraptor vs SIEM: kapan beralih, kapan cukup SIEM

Pertanyaan terakhir Dimas adalah soal disiplin tim: Velociraptor menyenangkan dipakai, dan justru karena itu L1 bisa tergoda membukanya untuk pertanyaan yang lebih cepat dijawab Splunk. Tabel berikut membandingkan keduanya; baca baris "Kapan unggul".

| Dimensi | SIEM (Splunk/Wazuh) | Velociraptor |
|---|---|---|
| Data | Log yang sudah dikirim dan dinormalkan | Artefak live di endpoint, termasuk yang tak pernah dikirim |
| Historis | Kuat (retensi panjang) | Terbatas (snapshot saat hunt; monitoring ke depan) |
| Jangkauan artefak | Hanya yang di-log | Registry mentah, prefetch, NTFS, memori, file |
| Korelasi lintas sumber | Kuat | Terbatas |
| Host yang tidak terhubung | Data lamanya tetap bisa dicari | Tidak menjawab sampai terhubung |
| Dampak ke endpoint | Tidak ada saat mencari | Ada (CPU, disk, jaringan), harus dibatasi |
| Kapan unggul | Analisis historis, korelasi | Artefak endpoint, verifikasi, triage fleet |

Pola yang umum: SIEM menandai host mencurigakan (Day 06, 08), lalu Velociraptor menjangkau host itu untuk artefak yang tidak ada di log (autoruns lengkap, prefetch, isi scheduled task). Keduanya saling melengkapi, bukan bersaing. Alur pivot dari SIEM ke endpoint:

1. Di Splunk atau Wazuh (Day 06, 08), stacking menemukan host yang menjalankan `mshta.exe` dan menghubungi IP eksternal.
2. Di Velociraptor, kumpulkan dari host itu: prefetch (kapan `mshta` dijalankan), scheduled task dan autoruns (persistence), koneksi jaringan, dan file di Temp (artefak tahap kedua).
3. Hash file yang ditemukan, cocokkan ke YARA/intel.
4. Bila terkonfirmasi, handover ke IR; bila pola layak dideteksi, handover ke DE.

Log memberi tahu "ada yang aneh di host ini"; Velociraptor menjawab "apa yang sebenarnya ada di host itu sekarang". Arah sebaliknya sama pentingnya: temuan endpoint menghasilkan indikator baru (domain, IP, nama file) yang lalu dicari di SIEM untuk mengetahui sejak kapan dan di host mana lagi. Bagian 2.6 memakai arah ini.

Aturan praktis yang diberikan ke tim, sebagai jawaban pertanyaan ketujuh:

- Pakai SIEM bila pertanyaannya "pernahkah", "sejak kapan", "berapa host dalam 30 hari", atau butuh menggabungkan sumber (proxy, DNS, VPN, autentikasi), dan sumbernya ada untuk host yang ditanya.
- Pakai Velociraptor bila pertanyaannya "apa yang ada di mesin sekarang", artefaknya tidak di-log, atau host targetnya tanpa Sysmon dan EDR.
- Bila ragu, mulai dari SIEM: tidak menyentuh endpoint, tidak butuh host online, dan hasilnya bisa diulang. Beralih ke endpoint saat SIEM menjawab "datanya tidak ada", bukan saat SIEM menjawab "tidak ditemukan".

## 2. Contoh dan langkah praktis: dua hunt persistence hari Kamis

Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi. Waktu di GUI dan hasil Velociraptor ditampilkan dalam UTC; di teks ditulis WIB (UTC+7) kecuali disebut lain. Query Splunk memakai rentang absolut dalam format `earliest="MM/DD/YYYY:HH:MM:SS"`. Nama artifact, parameter, dan fungsi VQL perlu dicek karena bergantung versi; untuk latihan, jalankan versi yang disesuaikan di lab pribadi (bagian 3).

### 2.1 Cakupan client Kamis pagi

Sebelum menjawab pertanyaan kelima Dimas dengan angka dan sebelum hunt apa pun, kamu perlu tahu berapa host yang sebenarnya bisa ditanya. Angka ini akan menjadi baris "cakupan" di kedua laporan.

**Tujuan:** menghitung client yang terdaftar dan yang terlihat online, per kelompok host, lalu membandingkannya dengan inventaris AD.

**Sintaks (notebook server):**

```
SELECT client_id, os_info.hostname AS Hostname, labels,
       timestamp(epoch=last_seen_at) AS LastSeen
FROM clients()
WHERE os_info.system = "windows"
ORDER BY LastSeen
```

| Bagian | Fungsi |
|---|---|
| `clients()` | Plugin server yang mengeluarkan satu baris per client terdaftar |
| `os_info.hostname`, `labels` | Nama host dan label client, untuk dicocokkan dengan ekspor AD `jab_assets.csv` |
| `timestamp(epoch=last_seen_at)` | Waktu terakhir client terhubung; satuan `last_seen_at` bisa berbeda antar versi, jadi cek bila tanggalnya tampak aneh |
| `WHERE os_info.system = "windows"` | Hanya client Windows |

Keluaran ilustrasi (diringkas per kelompok, dicocokkan dengan inventaris AD pukul 08:00):

```
Kelompok           Inventaris AD   Terdaftar di Velo   Belum terdaftar
Server Windows          61                61                 0
WS Jakarta             301               289                12
WS Bandung              58                47                11
WS Surabaya (POP)       13                 5                 8
WS Medan (POP)          10                 3                 7
Total                  443               405                38
```

**Cara membaca hasil:** 38 workstation belum terdaftar, hampir semuanya laptop yang belum tersambung ke jaringan kantor atau VPN sejak paket client dibagikan Senin. POP paling lemah: hanya 8 dari 23 workstation Surabaya dan Medan yang terdaftar. Salah satu yang terdaftar adalah `SBY-WS-0107`, laptop sales Surabaya, yang menerima paket Rabu 2027-02-24 pukul 19:40 saat penggunanya menyambungkan VPN dari rumah. Angka "terdaftar" belum berarti "akan menjawab hari ini"; itu baru terlihat dari hasil hunt.

**Variasi:** tambahkan `WHERE labels =~ "velo-canary"` untuk memeriksa anggota label canary sebelum hunt.

**Kapan gagal:** hostname di client berbeda dari nama di AD (huruf besar/kecil, FQDN vs nama pendek), sehingga pencocokan dengan inventaris meleset; normalisasi dulu ke huruf kecil tanpa domain.

### 2.2 `HUNT-2027-012`: abstract dan konfigurasi hunt autoruns

Hunt pertama ini menjawab permintaan Dimas "jalankan dua hunt persistence" sekaligus menguji beban yang ia khawatirkan. Pemicunya celah data yang sudah diketahui: 229 workstation tanpa Sysmon tidak pernah mengirim apa pun tentang autostart.

```
ID             : HUNT-2027-012
Dibuat         : Kamis 2027-02-25 08:30, pemilik: <kamu>, reviewer: Dimas Prasetyo
Trigger        : Celah data - autostart di host tanpa Sysmon tidak pernah terlihat di SIEM;
                 server Velociraptor permanen jkt-velo02 baru tersedia
Tipe (PEAK)    : Baseline (stacking lintas fleet)
Hipotesis      : Ada entri autostart di host Windows PT JAB yang hanya muncul di satu host,
                 tidak bertanda tangan atau menunjuk ke lokasi yang bisa ditulis pengguna,
                 yang menandakan persistence yang belum terdeteksi.
ATT&CK         : T1547 (Boot or Logon Autostart Execution, termasuk .001 Run keys dan .004 Winlogon),
                 T1543.003 (Windows Service), T1546.003 (WMI Event Subscription)
Data           : Windows.Sysinternals.Autoruns, kategori: Logon startups, Autostart services and
                 non-disabled drivers, WMI entries, Winlogon entries, Image hijacks, Appinit DLLs,
                 Known DLLs, LSA security providers; Verify digital signatures aktif
Di luar cakupan: Scheduled tasks (dikerjakan HUNT-2027-013); client yang tidak terhubung
                 sampai Kamis 16:00; workstation yang belum terdaftar
Kriteria sukses: Semua entri dengan hosts = 1 yang tidak bertanda tangan atau berada di lokasi
                 yang bisa ditulis pengguna sudah diberi label
Batas sumber   : timeout 900 s, max_rows 5.000, max_upload_bytes 1 MB (artifact ini tidak mengunggah file)
Urutan         : label velo-canary 09:00, seluruh client Windows (kecuali canary) 09:40
Handover       : IR (Dimas) bila ditemukan; Sari Kusuma untuk usulan deteksi; IT untuk software liar
```

Cara membaca elemennya:

- **Kategori dipilih, bukan `All`.** Parameter artifact berupa centang kategori: `All` (default aktif) atau per kategori seperti `Logon startups`, `Scheduled tasks`, `Autostart services and non-disabled drivers`, `WMI entries`, `Winlogon entries`, plus `Verify digital signatures` (default aktif) [S4]. Scheduled task sengaja dikeluarkan karena `HUNT-2027-013` membacanya lewat XML dengan kolom yang lebih kaya. Akibatnya, hasil "tidak ditemukan" di hunt ini tidak berlaku untuk scheduled task, dan baris "Di luar cakupan" menyebutnya.
- **`EXECVE` dan binary.** Karena menjalankan binary, artifact ini butuh izin `EXECVE` dan binary-nya harus tersedia di server (lab tanpa internet perlu mengunggahnya manual). `jkt-velo02` di jaringan manajemen tidak mengunduh dari internet, jadi `autorunsc64.exe` diunggah ke tool `Autorun_amd64` di server sebelum hunt.
- **Timeout 900 detik, bukan default 600.** `autorunsc` dengan verifikasi tanda tangan bisa lama di laptop tua, dan CPU limit tidak berlaku untuk proses eksternal (bagian 1.5). Satu-satunya rem adalah timeout dan canary.

Hasil canary (keluaran ilustrasi): 25 dari 25 client selesai sampai 09:31, durasi median 2 menit 40 detik, maksimum 7 menit 50 detik (satu server file), tidak ada keluhan pengguna, rata-rata 249 baris per host. Hunt seluruh fleet dimulai 09:40.

**Kapan gagal:** hunt dimulai langsung ke seluruh fleet dengan timeout default; laptop yang lambat dibatalkan di 600 detik dan diam-diam hilang dari cakupan, sementara laporan menulis "semua host".

### 2.3 `HUNT-2027-012`: stacking autoruns di notebook

Setelah hasil masuk, stacking dijalankan di notebook hunt. Query ini adalah inti hunt pertama dan bentuknya akan dipakai ulang di `HUNT-2027-013`.

**Tujuan:** menghitung berapa host yang memiliki setiap image path autostart, lalu melihat ujung yang paling jarang.

```
LET rows = SELECT ClientId, `Image Path` AS ImagePath,
       format(format="%v|%v", args=[ClientId, `Image Path`]) AS Key
FROM source(artifact="Windows.Sysinternals.Autoruns")

LET per_host = SELECT ClientId, ImagePath FROM rows GROUP BY Key

SELECT ImagePath, count() AS hosts
FROM per_host
GROUP BY ImagePath
ORDER BY hosts
```

- `source(artifact=...)` di notebook hunt membaca hasil gabungan hunt itu dari semua client; `ClientId` menandai asal tiap baris.
- `GROUP BY` di VQL membagi baris ke dalam bin per nilai, dan fungsi agregat seperti `count()` menyimpan state terpisah untuk tiap bin [S3]. Karena itu `count()` di query terakhir menghitung jumlah host per entri, sama dengan stacking `dc(host)` di SPL (Day 05).
- Hanya pilih kolom yang ikut di-`GROUP BY` atau hasil fungsi agregat; kolom lain di bin yang sama bisa berisi nilai apa saja [S3].
- Nama kolom berasal dari header CSV `autorunsc`, sehingga mengandung spasi dan ditulis dengan backtick. Header yang umum di keluaran `autorunsc` adalah `Entry Location`, `Entry`, `Enabled`, `Category`, `Profile`, `Description`, `Signer`, `Company`, `Image Path`, `Version`, `Launch String`, dan kolom hash; daftar persisnya tidak dirinci di dokumentasi artifact dan bisa berubah antar versi `autorunsc`, jadi cek di tabel hasil hunt lab sebelum menulis query.
- Untuk `Windows.Sys.StartupItems`, ganti `Image Path` dengan `OSPath` atau `Details`. Kolom StartupItems adalah `Name`, `OSPath`, `Details`, `Enabled`, `Upload` [S5].

Keluaran ilustrasi pada hunt PT JAB (ringkas, sampai Kamis 16:00):

```
Client yang menerima hunt      : 379 (61 server + 318 workstation)
Selesai                        : 375
Dibatalkan timeout (900 s)     : 4 (laptop lama Bandung)
Baris                          : 96.412
ImagePath unik                 : 3.106
ImagePath dengan hosts = 1     : 241
hosts = 1 dan (Signer kosong/tidak terverifikasi atau path di \users\, \appdata\,
               \programdata\, \temp\)                                   : 14
```

Penyaringan tahap terakhir memakai kolom yang membantu menilai entri langka: `Signer` (entri tanpa tanda tangan atau ditandatangani penerbit tak dikenal lebih mencurigakan), `Entry Location` (Run key, service, task), dan `Launch String` (argumen lengkap). Versi query dengan filter itu menambahkan `Signer` ke tahap pertama dan memfilter di tahap terakhir; nilai `Signer` dari `autorunsc` biasanya diawali penanda status verifikasi, jadi cek bentuk persisnya di hasil lab sebelum menulis regex.

Ke-14 entri ditinjau satu per satu dengan pivot ke `Launch String`, pengguna host, dan tiket IT. Tabel berikut adalah hasil tinjauan; baca kolom "Alasan jinak", karena di sanalah konfirmasinya.

| Kelompok | Jumlah | Contoh | Alasan jinak |
|---|---|---|---|
| Updater per-user di Run key HKCU | 6 | Updater aplikasi rapat dan pembaca dokumen di `AppData\Local` | Software terdaftar di katalog IT, ditandatangani vendor; tanda tangan tidak terverifikasi karena cache sertifikat di laptop |
| Tool portabel admin IT | 4 | Service inventaris di `C:\ProgramData\JAB-IT\` | Tiket IT, dipasang tim helpdesk |
| Helper driver printer tanpa tanda tangan | 2 | Service di `Program Files (x86)` dua workstation Keuangan | Driver printer lama, dikonfirmasi IT |
| Dashboard modem USB | 1 | Run key di laptop sales Medan | Dipasang bersama modem dari vendor seluler |
| Service sisa uninstall VPN lama | 1 | Image path tidak ditemukan di disk | Sisa uninstall; tiket pembersihan ke IT |

**Cara membaca hasil:** 14 entri langka, semua jinak. `C:\Users\Public\updater.exe` di satu host, seandainya muncul, akan menjadi kandidat kuat untuk di-pivot ke artifact lain (prefetch, proses) di host itu; di hunt ini tidak ada entri seperti itu. Hasilnya tidak ditemukan untuk kategori yang dipilih, di 375 host yang selesai. Untuk scheduled task, hunt ini tidak berkata apa-apa.

**Variasi:** stacking per `Entry Location` dan `Entry` (bukan path) menemukan entri dengan nama sama yang menunjuk ke path berbeda di satu host, pola yang muncul bila penyerang meniru nama updater sah.

**Kapan gagal:** stacking dihitung langsung `SELECT ImagePath, count() ... GROUP BY ImagePath` tanpa tahap per host, sehingga `count()` menghitung baris, bukan host, dan entri yang muncul berkali-kali di satu host terlihat tersebar; atau path tidak dinormalisasi sehingga satu updater per-user terpecah menjadi puluhan "entri langka" karena nama folder pengguna berbeda.

### 2.4 `HUNT-2027-013`: scheduled task lintas fleet

Hunt kedua menjalankan hipotesis yang sudah menunggu di backlog. `HUNT-2027-004` (Day 07) berburu scheduled task lewat Event ID 4698 dan Sysmon dan berakhir tidak ditemukan, dengan celah data tertulis: 229 workstation di luar OU `Workstations-EDR` tidak mengirim 4698 maupun Sysmon. Celah itu masuk backlog sebagai `HUNT-2027-009`, "scheduled task di host tanpa audit, butuh koleksi endpoint". Dengan `jkt-velo02`, koleksi endpoint itu kini ada, dan `HUNT-2027-013` adalah pelaksanaannya.

```
ID             : HUNT-2027-013 (pelaksanaan backlog HUNT-2027-009)
Dibuat         : Kamis 2027-02-25 08:45, pemilik: <kamu>, reviewer: Dimas Prasetyo
Trigger        : Celah data HUNT-2027-004: tanpa 4698 dan Sysmon di 229 workstation
Tipe (PEAK)    : Hypothesis-driven, analisis dengan stacking
Hipotesis      : Ada scheduled task di host Windows PT JAB yang hanya terdaftar di satu atau dua host
                 dan aksinya menjalankan program dari lokasi yang bisa ditulis pengguna
                 (\Users\, \AppData\, \ProgramData\, \Temp\) atau script host, tanpa alasan sah.
ATT&CK         : T1053.005 Scheduled Task (v20: Execution, Persistence, Privilege Escalation)
Data           : Windows.System.TaskScheduler (source Analysis), semua client Windows
Di luar cakupan: Client yang tidak terhubung sampai Kamis 16:00; workstation yang belum terdaftar;
                 task tersembunyi yang tidak meninggalkan file XML (belum diuji)
Kriteria sukses: Semua pasangan (nama task, path aksi) dengan hosts <= 2 dan path yang bisa ditulis
                 pengguna sudah diberi label
FP yang diduga : Updater per-user (OneDrive, aplikasi rapat), skrip IT di ProgramData
Batas sumber   : timeout 600 s, max_rows 2.000, tanpa upload
Handover       : IR (Dimas) bila ditemukan; Agung untuk celah audit; Sari untuk usulan deteksi
```

Artifact ini ringan: ia tidak menjalankan binary eksternal, hanya meng-glob dan mem-parse file XML, sehingga langsung dijalankan ke seluruh client Windows pukul 09:20 tanpa canary terpisah.

**Tujuan query pertama:** memfilter task yang aksinya menunjuk ke lokasi user-writable atau script host, seperti query lama yang dipakai di lab.

```
SELECT ClientId, TaskName, Command, Arguments, UserId, ComHandler, RegistrationTime
FROM source(artifact="Windows.System.TaskScheduler/Analysis")
WHERE Command =~ '(?i)users.public|appdata|powershell|mshta'
   OR Arguments =~ '(?i)users.public|appdata|powershell|mshta|http'
ORDER BY ClientId
```

- `Windows.System.TaskScheduler` [S6] meng-glob file XML definisi task di `C:/Windows/System32/Tasks/**`, mem-parse XML-nya, dan mengeluarkan kolom `TaskName`, `Mtime`, `Command`, `Arguments`, `UserId`, `RunLevel`, `LogonType`, `ComHandler`, `RegistrationTime`, `StartBoundary`, `OSPath`, plus `Authenticode` binary yang dijalankan. Artifact ini punya source bernama `Analysis`, sehingga `source()` memakai `Windows.System.TaskScheduler/Analysis`.
- `Command` sudah dinormalisasi: variabel lingkungan diekspansi, hanya path binary yang diambil, dan semuanya diubah ke huruf kecil. Argumen ada di kolom `Arguments` terpisah, karena itu filter diterapkan ke keduanya.
- `=~` adalah operator regex VQL dan sudah tidak peka huruf besar/kecil secara default [S3], sehingga `(?i)` di sini tidak wajib tetapi tidak merugikan. Titik di `users.public` cocok dengan backslash sehingga tidak perlu escape berlapis.
- Task yang aksinya COM handler, bukan program, punya `Command` kosong dan `ComHandler` berisi CLSID; tinjau terpisah dengan `WHERE ComHandler`.
- Parameter artifact: `TasksPath` (default `C:/Windows/System32/Tasks/**`), `AlsoUpload`, `UploadCommands`, dan `Username` (regex atas `UserId`, default `.*`) [S6].
- Kenapa endpoint penting di sini: event pembuatan task (Security 4698 atau Task Scheduler Operational 106) bergantung pada audit policy dan channel yang dikumpulkan, dan task yang dibuat lewat COM/API Task Scheduler langsung atau disalin ke folder Tasks bisa saja tidak meninggalkan jejak di log yang kamu kirim ke SIEM. File XML di disk tetap ada selama task terdaftar, jadi artifact ini melihatnya terlepas dari konfigurasi logging (ATT&CK T1053.005 [S7]).

Query pertama di PT JAB menghasilkan 1.904 baris, kebanyakan task OneDrive dan updater per-user yang memang berada di `AppData`. Terlalu banyak untuk ditinjau satu per satu, persis seperti long tail mentah di `HUNT-2027-001`. Karena itu langkah berikutnya adalah stacking dengan normalisasi.

**Tujuan query kedua:** menumpuk pasangan nama task dan path aksi per host, setelah nama pengguna dan GUID/SID di nama task dinormalisasi, lalu melihat pasangan yang hanya ada di satu atau dua host dengan path yang bisa ditulis pengguna.

```
LET tasks = SELECT ClientId,
       regex_replace(source=TaskName,
                     re='''-S-1-5-21-[0-9-]+|\{[0-9A-Fa-f-]{36}\}''', replace='') AS TaskN,
       regex_replace(source=Command,
                     re='''\\users\\[^\\]+\\''', replace='''\users\<user>\''') AS CommandN,
       Arguments
FROM source(artifact="Windows.System.TaskScheduler/Analysis")

LET per_host = SELECT TaskN, CommandN, ClientId,
       format(format="%v|%v", args=[TaskN, CommandN]) AS Pair,
       format(format="%v|%v|%v", args=[TaskN, CommandN, ClientId]) AS Key
FROM tasks
WHERE CommandN =~ '''\\users\\|\\appdata\\|\\programdata\\|\\temp\\'''
   OR Arguments =~ '''\\users\\|\\appdata\\|\\programdata\\|\\temp\\'''
GROUP BY Key

LET stack = SELECT TaskN, CommandN, count() AS hosts,
       enumerate(items=ClientId) AS clients
FROM per_host
GROUP BY Pair

SELECT * FROM stack WHERE hosts <= 2 ORDER BY hosts
```

| Bagian | Fungsi |
|---|---|
| `regex_replace(source=TaskName, ...)` | Membuang akhiran SID dan GUID yang membuat task per-user (misalnya updater OneDrive) tampak unik di setiap host |
| `regex_replace(source=Command, ...)` | Mengganti `\users\<nama>\` dengan `\users\<user>\`, padanan normalisasi path di Day 05 |
| String `'''...'''` | String mentah; `\\` di regex cocok dengan satu backslash |
| `WHERE CommandN =~ ... OR Arguments =~ ...` | Hanya aksi di lokasi yang bisa ditulis pengguna, di binary maupun argumennya |
| `GROUP BY Key` | Tahap 1: satu baris per pasangan dan host |
| `count()`, `enumerate(items=ClientId)` di `GROUP BY Pair` | Tahap 2: jumlah host per pasangan dan daftar client-nya |
| `SELECT * FROM stack WHERE hosts <= 2` | Filter atas hasil agregat dilakukan di luar `GROUP BY` |

Nama fungsi `regex_replace()` dan `enumerate()` beserta argumennya perlu diuji di notebook lab sebelum dipakai; bila `enumerate` tidak tersedia di versi-mu, buang kolom itu dan cari client-nya dengan query terpisah.

Keluaran ilustrasi (statistik):

```
Client yang menerima hunt         : 379 (61 server + 318 workstation), semua selesai
Baris                             : 61.006 (rata-rata 161 task per host)
TaskName unik mentah / normalisasi: 1.214 / 418
Pasangan (TaskN, CommandN) dengan path user-writable : 63
... dengan hosts <= 2             : 5
```

Keluaran ilustrasi (lima pasangan):

```
TaskN                          CommandN                                                     hosts clients
\PDFSuite Updater              c:\users\<user>\appdata\local\pdfsuite\pdfupdater.exe          1   SBY-WS-0107
\GrammarPal Update             c:\users\<user>\appdata\local\grammarpal\update.exe            1   JKT-WS-0588
\PhotoSync Backup              c:\users\<user>\appdata\local\photosync\psync.exe              1   MDN-WS-0011
\VidConf UpdateTask            c:\users\<user>\appdata\roaming\vidconf\bin\vcupdater.exe      2   JKT-WS-0614, BDG-WS-0207
\JAB-IT Inventaris Sekali      c:\windows\system32\windowspowershell\v1.0\powershell.exe      2   JKT-WS-0623, JKT-WS-0624
```

**Cara membaca hasil:** pasangan terakhir lolos karena argumennya (`-File C:\ProgramData\JAB-IT\inv.ps1`), bukan karena binary-nya. Empat pasangan bawah ditinjau dan diberi label jinak: `VidConf` adalah updater aplikasi rapat dari katalog IT; `JAB-IT Inventaris Sekali` dibuat helpdesk untuk dua PC baru (tiket IT); `GrammarPal` dan `PhotoSync` adalah aplikasi pribadi yang dipasang pengguna, ditandatangani vendornya, dan diteruskan ke IT sebagai pelanggaran kebijakan software, bukan insiden. Pasangan pertama dibahas di bagian 2.5.

**Variasi:** stacking per `UserId` dan `RunLevel` untuk task yang berjalan sebagai SYSTEM dengan aksi di lokasi user-writable, kombinasi yang lebih jarang dan lebih berbahaya; atau `WHERE ComHandler` untuk task COM.

**Kapan gagal:** nama task per-user tidak dinormalisasi, sehingga ratusan task OneDrive tampak unik dan menenggelamkan yang penting; filter hanya memeriksa `Command`, sehingga task yang menjalankan `powershell.exe` dari System32 dengan skrip di `AppData` lolos; atau filter "tidak bertanda tangan" dipakai sebagai syarat, padahal kolom `Authenticode` menilai binary di `Command`, dan binary itu bisa saja sah (bagian 2.5).

### 2.5 Membaca baris `\PDFSuite Updater` di `SBY-WS-0107`

Hasil `SBY-WS-0107` masuk pukul 10:53, satu menit setelah penggunanya, Rani Oktaviani (`rani.oktaviani`, sales POP Surabaya), menyambungkan VPN dari rumah. Pukul 11:05, saat notebook dijalankan ulang, pasangan itu muncul. Baris mentahnya:

```
ClientId          : C.4e1a9b07d2c3f815    (SBY-WS-0107)
TaskName          : \PDFSuite Updater
Command           : c:\users\rani.oktaviani\appdata\local\pdfsuite\pdfupdater.exe
Arguments         :
UserId            : JAB\rani.oktaviani
LogonType         : InteractiveToken
RegistrationTime  : 2026-12-05T03:41:52Z     (Sabtu 2026-12-05 10:41:52 WIB)
OSPath            : C:\Windows\System32\Tasks\PDFSuite Updater
Authenticode      : Trusted, subject "Northwind Media Tools Inc."
```

Lima hal membuat baris ini berbeda dari empat pasangan lain:

1. **Nama task dan folder sama dengan `INC-2026-026`.** Pada insiden installer PDF palsu Desember 2026, persistence-nya adalah scheduled task `\PDFSuite Updater` saat logon yang menjalankan `pdfupdater.exe` dari `AppData\Local\PDFSuite`, folder yang juga berisi `version.dll` tidak bertanda tangan dan `update.dat`.
2. **Waktunya.** Task terdaftar Sabtu 2026-12-05, sehari setelah laptop Bandung `BDG-WS-0163` menjalankan installer yang sama pada Jumat 2026-12-04 15:05.
3. **Host-nya.** `SBY-WS-0107` tanpa MDE dan tanpa Sysmon, satu dari 23 workstation POP yang sama sekali tidak punya telemetri endpoint di SIEM.
4. **Tanda tangan sah tidak berarti aman.** `pdfupdater.exe` bertanda tangan vendor fiktif "Northwind Media Tools Inc.", sama seperti di `INC-2026-026`. Pola yang dipakai di insiden itu adalah DLL side-loading: program bertanda tangan memuat `version.dll` berbahaya dari foldernya sendiri. Di ATT&CK v20, side-loading masuk ke T1574.001 Hijack Execution Flow: DLL, yang mencakup side-loading, search order hijacking, dan phantom DLL [S20]; T1574.002 tidak lagi tercantum sebagai sub-teknik terpisah [S21].
5. **Kontras dengan aplikasi sah.** `JAB DocSync` juga membawa `version.dll` di samping executable-nya, di 214 perangkat, tetapi lokasinya `C:\Program Files\JAB DocSync\` dan DLL-nya bertanda tangan PT JAB. `version.dll` di samping executable bukan sinyal sendirian; lokasinya, tanda tangannya, dan prevalence-nya yang membedakan.

Bahkan tanpa kecocokan nama dengan `INC-2026-026`, pasangan ini akan berlabel "perlu investigasi": satu host, path user-writable, trigger logon, dan host tanpa telemetri. Kecocokan nama hanya mempercepat keputusan.

### 2.6 Kenapa IOC `INC-2026-026` tidak menemukan host ini

Pertanyaan pertama Dimas setelah mendengar temuan ini pasti "kenapa scoping Desember tidak menemukannya?". Jawabannya penting untuk laporan dan untuk program, karena ia menunjukkan batas pencarian IOC (HMM1) dibanding hunt berbasis pola. Pivot balik ke SIEM menjawabnya.

**Tujuan query pertama:** memastikan apakah laptop itu pernah memakai resolver PT JAB untuk domain keluarga PDFSuite, dan kapan.

```
index=dns sourcetype=isc:bind:query
    earliest="01/26/2027:00:00:00" latest="02/25/2027:12:00:00"
    query="*pdfsuite*"
| eval day=strftime(_time, "%Y-%m-%d")
| stats count AS queries dc(src) AS clients values(src) AS src_list BY host query day
| sort day
```

| Bagian | Fungsi |
|---|---|
| `earliest="01/26/2027..."` | Batas awal retensi `dns` 30 hari pada hari itu; data sebelum itu sudah tidak ada |
| `query="*pdfsuite*"` | Mencakup domain lama dan varian; wildcard di depan mahal untuk sekitar 15,6 juta event per hari |
| `stats ... BY host query day` | Resolver mana, domain apa, hari apa |

Keluaran ilustrasi:

```
host       query                             day          queries  clients  src_list
sby-res01  cdn.pdfsuite-cloud.example.net    2027-02-04   97       1        10.40.12.107
sby-res01  cdn.pdfsuite-cloud.example.net    2027-02-16   115      1        10.40.12.107
```

**Cara membaca hasil:** 212 query dalam 30 hari, semuanya dari `10.40.12.107` (alamat `SBY-WS-0107` di kantor POP Surabaya), hanya pada dua hari ketika Rani bekerja dari kantor. Domainnya `cdn.pdfsuite-cloud.example.net`, bukan `cdn.pdfsuite-update.example.net` yang ada di daftar IOC `INC-2026-026`. Domain lama tidak muncul sama sekali.

**Tujuan query kedua:** memastikan dari mana installer dijalankan.

```
index=vpn sourcetype=pan:globalprotect "rani.oktaviani"
    earliest="12/03/2026:00:00:00" latest="12/09/2026:00:00:00"
| bin _time span=1d
| stats count AS events BY _time
```

Pencarian memakai teks bebas, bukan nama field, karena nama field add-on GlobalProtect perlu dicek di lingkunganmu; retensi `vpn` juga perlu dipastikan mencakup Desember. Keluaran ilustrasi: event pada 3, 4, 7, dan 8 Desember, tidak ada pada Sabtu 5 Desember. Installer dijalankan Sabtu pukul sekitar 10:38 tanpa VPN (prefetch di bagian 2.7), dari koneksi rumah.

**Tujuan query ketiga:** memastikan kenapa Security log tidak membantu.

```
| tstats count WHERE index=wineventlog host=SBY-WS-0107
    earliest="02/18/2027:00:00:00" latest="02/25/2027:00:00:00" BY EventCode
| sort - count
```

Keluaran ilustrasi: 4624, 4634, 4672, 4648, dan beberapa lainnya; tidak ada 4698. Host ini mengirim Security log, tetapi audit Other Object Access tidak aktif karena GPO `JAB-WS-Audit` tidak ditautkan ke OU POP.

Gabungan ketiga query dan baris Velociraptor menjelaskan kenapa IOC tidak menemukannya. Tabel berikut memisahkan tiap lapis pencarian `INC-2026-026`; baca kolom kanan untuk alasan lapis itu buta terhadap host ini.

| Lapis pencarian saat `INC-2026-026` | Kenapa tidak menemukan `SBY-WS-0107` |
|---|---|
| Domain dan IP C2 (`cdn.pdfsuite-update.example.net`, `198.51.100.37`) di `proxy`, `dns`, `firewall` | Varian ini memakai `cdn.pdfsuite-cloud.example.net` (`198.51.100.39`), tidak ada di daftar; dari rumah, trafiknya tidak lewat proxy dan resolver PT JAB karena split tunnel |
| Unduhan installer di proxy | Diunduh dan dijalankan dari rumah tanpa VPN |
| SHA1 `version.dll` dan custom detection perilaku di MDE | Host tanpa MDE; hash varian ini juga berbeda (bagian 2.7) |
| Nama task `\PDFSuite Updater` | Hanya bisa dicari di host yang mengirim 4698 atau Sysmon; host ini tidak mengirim keduanya |
| Hunt beacon `HUNT-2027-005` (Day 05) | Cakupannya proxy Jakarta dan Bandung (`10.10.0.0/16`, `10.30.0.0/16`); POP Surabaya di luar cakupan |

Yang menemukannya adalah pola persistence yang dibaca langsung dari disk, bukan indikator. Itu contoh nyata Pyramid of Pain: domain dan hash sudah berganti, tetapi cara bertahan (task saat logon, executable bertanda tangan di `AppData`, DLL di sampingnya) tidak.

**Kapan gagal:** pivot balik dihentikan setelah `dns` kosong untuk domain lama. Mencari pola nama (`*pdfsuite*`) alih-alih indikator persis yang membuat varian terlihat.

### 2.7 Pengumpulan terarah awal yang aman

Begitu baris itu terbaca, ada satu pertimbangan waktu: laptop sedang tersambung VPN dan bisa terputus kapan saja. Kumpulkan bukti yang hilang bila laptop dimatikan atau pengguna sadar, tetapi tanpa mengubah keadaan host: tanpa menjalankan, membuka, atau membedah file mencurigakan, dan tanpa menghapus apa pun. Keputusan selanjutnya milik IR.

Collection dijalankan pukul 11:08 ke `SBY-WS-0107` saja (bukan hunt), dengan `max_upload_bytes` 50 MB dan timeout default. Tabel berikut adalah daftar artifact yang dipakai; baca kolom "Kenapa aman" sebagai alasan artifact itu boleh dijalankan sebelum IR memutuskan.

| Artifact | Parameter | Yang dicari | Kenapa aman |
|---|---|---|---|
| `Windows.System.TaskScheduler` [S6] | `TasksPath` = `C:/Windows/System32/Tasks/PDFSuite Updater`, `AlsoUpload` = Y | Salinan file XML task | Hanya membaca dan menyalin file definisi |
| `Windows.Search.FileFinder` [S8] | Glob `C:\Users\rani.oktaviani\AppData\Local\PDFSuite\*`, `Calculate_Hash` = Y, `Upload_File` = Y | Daftar file, ukuran, waktu, hash, salinan file | Membaca dan menyalin; file tidak dijalankan |
| `Windows.Forensics.Prefetch` [S22] | `binaryRegex` = `pdfsuite\|pdfupdater` | Kapan installer dan `pdfupdater.exe` dijalankan, berapa kali | Hanya mem-parse file `.pf` |
| `Windows.System.DNSCache` [S23] | (default) | Domain yang baru di-resolve | Query WMI ke cache DNS client |
| `Windows.Network.NetstatEnriched` [S24] | `ProcessNameRegex` = `pdfupdater`; `KillProcess` dan `DumpProcess` tidak dicentang | Koneksi aktif `pdfupdater.exe` beserta tanda tangannya | Hanya membaca; butuh `EXECVE`, dan dua opsi aksinya berbahaya bila dicentang |

Beberapa catatan parameter dari referensi artifact:

- Parameter `AlsoUpload` di TaskScheduler dideklarasikan bool, tetapi query-nya membandingkan dengan nilai `'Y'` [S6]; bila salinan XML tidak muncul, periksa nilainya. `UploadCommands` sengaja tidak dipakai karena `pdfupdater.exe` sudah diambil lewat FileFinder.
- FileFinder punya parameter `SearchFilesGlobTable` (daftar glob), `Accessor` (`auto`, `ntfs`, `ntfs_vss`, dan lain-lain), `YaraRule`, `Calculate_Hash`, `Upload_File`, `MoreRecentThan`, dan `ModifiedBefore` [S8]. Kolom hash ada di `Hash`.
- Prefetch di Windows 10 menyimpan sampai delapan waktu eksekusi terakhir [S22].
- NetstatEnriched menyediakan `KillProcess` dan `DumpProcess` yang berlaku ke semua baris yang cocok tanpa pengaman [S24]. Membunuh proses atau membuat dump memori adalah tindakan IR, bukan langkah hunt.

Keluaran ilustrasi (diringkas, waktu UTC):

```
FileFinder
OSPath                                                          Size       MTime                 Hash.SHA1
C:\Users\rani.oktaviani\AppData\Local\PDFSuite\pdfupdater.exe   1.482.240  2026-12-05T03:41:30Z  6d0a1c95...
C:\Users\rani.oktaviani\AppData\Local\PDFSuite\version.dll        214.528  2026-12-05T03:41:30Z  9b1e47d2...
C:\Users\rani.oktaviani\AppData\Local\PDFSuite\update.dat           3.104  2026-12-05T03:41:31Z  c47f0e18...

Prefetch
Executable               RunCount  LastRunTimes (terbaru)
PDFSUITE_SETUP_4.2.EXE   1         2026-12-05T03:38:12Z
PDFUPDATER.EXE           61        2027-02-25T03:49:58Z, ...

DNSCache
Name                              Record          RecordType  TTL
cdn.pdfsuite-cloud.example.net    198.51.100.39   A           241

NetstatEnriched
Name            Pid   Status       Raddr           Rport  Authenticode
pdfupdater.exe  6120  ESTABLISHED  198.51.100.39   443    Trusted (Northwind Media Tools Inc.)
```

**Cara membaca hasil:**

- Installer berjalan Sabtu 2026-12-05 10:38 WIB, file dijatuhkan 10:41, task terdaftar 10:41:52. `pdfupdater.exe` sudah berjalan 61 kali, terakhir Kamis pagi 10:49 WIB saat Rani logon. Persistence ini aktif sekitar 82 hari.
- SHA1 `version.dll` (`9b1e47d2...`) berbeda dari indikator `INC-2026-026` (`3f9c2b7e...`). Pencarian hash pun tidak akan menemukannya.
- Saat ini `pdfupdater.exe` memegang koneksi ke `198.51.100.39:443`, alamat yang di-resolve dari `cdn.pdfsuite-cloud.example.net`. Karena split tunnel, koneksi itu keluar langsung dari internet rumah Rani, tidak lewat firewall PT JAB.
- `update.dat` diambil sebagai file dan di-hash, tidak dibuka. Dugaan bahwa konfigurasi varian ini ada di file itu, seperti di `INC-2026-026`, diserahkan ke IR untuk dianalisis.

Ketiga file dan file XML task disimpan di collection Velociraptor dengan flow ID yang dicatat di laporan; hash dicatat di pesan handover supaya IR bisa memasukkannya ke evidence log.

**Variasi (VQL mentah):** artifact pencarian file bisa disalin dan diubah `WHERE`-nya, alih-alih menulis dari nol. Versi VQL mentahnya kira-kira seperti ini, misalnya untuk mencari executable di Temp setiap pengguna:

```
SELECT OSPath, Size, Mtime, hash(path=OSPath).SHA256 AS sha256
FROM glob(globs="C:\\Users\\*\\AppData\\Local\\Temp\\*.exe")
WHERE Size < 5000000
```

- `glob()` mencari file sesuai pola dan mengeluarkan kolom seperti `OSPath`, `Size`, `Mtime`; `hash()` menghitung MD5, SHA1, dan SHA256.
- Artifact bawaan versi 0.77.x memakai kolom `OSPath` dari `glob()`; contoh VQL lama di internet kadang memakai `FullPath`. Bila query lama gagal, cek nama kolom di hasil `glob()` lab.
- Ini pertanyaan endpoint yang tidak bisa dijawab log biasa: executable di folder Temp tiap user, dengan hash untuk dicocokkan ke daftar IOC atau rule YARA (rule pola byte/string untuk mengenali file). `Windows.Search.FileFinder` bisa langsung menerapkan YARA lewat parameter `YaraRule`.

**Kapan gagal:** pengumpulan ditunda sampai laporan selesai, laptop terputus pukul 11:58, dan bukti volatil (cache DNS, koneksi aktif) hilang; atau "pengumpulan" melebar ke menjalankan `pdfupdater.exe` di sandbox atau membuka `update.dat` di editor, yang mengubah bukti dan melampaui peran hunt.

### 2.8 Eskalasi sekarang dan handover ke IR

Hunt yang menemukan aktivitas berbahaya berhenti menjadi hunt begitu indikasinya kuat (Day 01 bagian 1.2). Persistence aktif dengan koneksi C2 yang sedang terbuka tidak menunggu laporan sore.

Pukul 11:12, saat collection masih berjalan, kamu mengirim pesan ke Dimas:

```
[11:12] HUNT-2027-013 menemukan persistence aktif yang cocok dengan pola INC-2026-026.
Host     : SBY-WS-0107 (rani.oktaviani, sales POP Surabaya), tanpa MDE dan tanpa Sysmon,
           sekarang online lewat VPN dari rumah (sejak 10:52)
Temuan   : scheduled task \PDFSuite Updater, terdaftar Sabtu 2026-12-05 10:41 WIB,
           menjalankan C:\Users\rani.oktaviani\AppData\Local\PDFSuite\pdfupdater.exe saat logon
Beda     : domain C2 bukan yang ada di IOC INC-2026-026 (detail menyusul)
Sedang   : pengumpulan read-only (task XML, isi folder PDFSuite + hash, prefetch, DNS cache,
           netstat). Tidak ada yang dijalankan, dihapus, atau diisolasi.
Minta    : keputusan IR sekarang; laptop bisa terputus kapan saja
```

Pukul 11:30 kamu menyusulkan hasil collection dan pivot `dns`. Pukul 11:40 Dimas menyatakan `INC-2027-040`, SEV-3, dengan Rudi Hartanto sebagai team lead. Handover singkat lewat panggilan pukul 11:45 menyerahkan paket berikut:

```
Handover HUNT-2027-013 -> INC-2027-040 (Kamis 2027-02-25 11:45 WIB, ke Rudi Hartanto)
Host/akun  : SBY-WS-0107 / rani.oktaviani; IP kantor 10.40.12.107; client C.4e1a9b07d2c3f815
Timeline   : 2026-12-05 10:38 installer (prefetch), 10:41 file dan task; 61 run pdfupdater.exe,
             terakhir 2027-02-25 10:49; DNS sby-res01 2027-02-04 (97) dan 2027-02-16 (115)
Indikator  : cdn.pdfsuite-cloud.example.net / 198.51.100.39:443 (aktif 11:2x)
             SHA1 version.dll 9b1e47d2..., pdfupdater.exe 6d0a1c95..., update.dat c47f0e18...
Bukti      : collection Velociraptor (flow ID di laporan): task XML, 3 file, prefetch, DNS cache, netstat
Belum      : update.dat belum dibuka; host lain belum dicari; tidak ada tindakan di host
Cakupan    : HUNT-2027-013 menjangkau 379/443 host; 64 workstation belum terjangkau (17 di POP)
```

Langkah IR berikutnya bukan milik hunt dan hanya disebut di sini: keputusan containment (host tanpa MDE, sehingga opsi yang tersedia antara lain artifact `Windows.Remediation.Quarantine` milik Velociraptor yang memblokir semua trafik kecuali DNS, DHCP, dan server Velociraptor lewat IPsec, dan butuh izin `EXECVE` serta `NETWORK` [S25], atau menarik laptop lewat manajer POP), pemblokiran indikator baru, scoping host lain untuk varian ini, dan analisis `update.dat`. Laptop terputus dari VPN pukul 11:58, sehingga opsi apa pun yang lewat Velociraptor harus menunggu ia tersambung lagi.

Begitu `INC-2027-040` dinyatakan, mencari host lain yang memiliki folder `PDFSuite` atau domain varian ini adalah scoping IR, walaupun memakai hunt Velociraptor yang sama. Peranmu bergeser menjadi pendukung bila diminta Rudi.

**Kapan gagal:** temuan disimpan untuk laporan sore "supaya lengkap"; atau hunter mengisolasi host sendiri karena tombolnya ada, sehingga keputusan containment diambil tanpa IC dan tanpa mempertimbangkan dampaknya ke pengguna dan bukti.

### 2.9 Client monitoring yang diusulkan

Pertanyaan keenam Dimas dijawab dengan usulan, bukan dengan menyalakan sesuatu ke seluruh fleet. Temuan hari ini memperkuat alasannya: di host tanpa telemetri, snapshot mingguan menemukan persistence setelah 82 hari; aliran event akan melihat installer saat dijalankan.

Untuk menangkap proses berumur pendek yang terlewat snapshot, pasang artifact monitoring yang menerapkan Sigma [S2]:

- `Windows.Events.ProcessCreation` adalah artifact bertipe `CLIENT_EVENT` yang menangkap pembuatan proses lewat WMI `Win32_ProcessStartTrace` dan memperkaya dengan parent serta call chain [S9]. Dokumentasinya sendiri menyebut metode ini kalah andal dibanding Sysmon dan menyarankan `Windows.Sysinternals.SysmonLogForward` bila Sysmon terpasang.
- `Windows.Sigma.EventLogs` mengevaluasi rule Sigma (inline atau file unggahan, dipisah baris `---`) terhadap file EVTX di endpoint, dengan pemetaan `process_creation/windows` ke log Sysmon Operational [S10]. Ini collection, bukan monitoring, dan dokumentasinya menyebutnya artifact demonstrasi; untuk set rule yang lebih lengkap, dokumentasi merujuk ke `Server.Import.CuratedSigma` yang mengimpor kumpulan rule terkurasi.
- Hasil artifact monitoring mengalir ke server secara real-time.

Rule Sigma yang sama bisa dipakai sebagai monitoring endpoint, bukan hanya dikonversi ke query SIEM. Artifact monitoring Sigma real-time yang diterbitkan proyek Velociraptor Sigma adalah `Windows.ETW.Monitoring` dan `Windows.Hayabusa.Monitoring` [S19]; isi rule dan sumber yang dipakai masing-masing perlu dicek di server lab sebelum dipasang.

Usulan ke Dimas (keputusan minggu depan):

```
Pilot      : label pop-no-edr (23 workstation POP Surabaya dan Medan tanpa MDE dan Sysmon),
             mulai setelah semuanya terdaftar
Artifact   : Windows.Events.ProcessCreation (sumber WMI; bukan pengganti Sysmon)
Ukur 2 mgg : event per host per hari, keterlambatan, ukuran buffer saat laptop di luar VPN,
             keluhan pengguna
Bukan      : Sigma real-time ke seluruh fleet minggu ini; rule process_creation berbasis log
             Sysmon tidak punya sumber di host-host ini
Keluar     : dihentikan begitu rollout Sysmon tahap pertama (Bandung + POP) selesai
```

**Kapan gagal:** monitoring dinyalakan ke semua label "All" tanpa mengukur volume; event dari ratusan host mengisi disk server, dan tidak ada yang membacanya karena belum ada query sisi server yang bereaksi atasnya.

### 2.10 Laporan kedua hunt, backlog turunan, dan jawaban untuk Dimas

Laporan ditulis Kamis sore setelah handover, dengan cakupan dibekukan pukul 16:00.

```
ID            : HUNT-2027-012                               Selesai: Kamis 2027-02-25 16:00
Hasil         : Tidak ditemukan (kategori autostart terpilih, tanpa scheduled task)
Cakupan nyata : 375 host selesai dari 443 host Windows di AD (61 server, 314 workstation)
                Tidak terjangkau: 38 workstation belum terdaftar, 26 terdaftar tapi offline,
                4 dibatalkan timeout (dijadwalkan ulang dengan timeout 1.800 s)
Jinak         : 14 entri langka (6 updater per-user, 4 tool IT, 2 driver printer, 1 dashboard modem,
                1 service sisa uninstall)
Beban         : canary 25 host median 2m40s, maks 7m50s; tanpa keluhan
Tindak lanjut : 2 tiket ke IT (service sisa, software liar); baseline autoruns disimpan dari notebook
```

```
ID            : HUNT-2027-013 (backlog HUNT-2027-009)       Selesai: Kamis 2027-02-25 16:00
Hasil         : DITEMUKAN - handover ke IR 11:45, INC-2027-040 SEV-3 (TL Rudi Hartanto)
Cakupan nyata : 379 dari 443 host Windows (61 server, 318 workstation = 83,2% workstation)
                Tidak terjangkau: 64 workstation (Jakarta 23, Bandung 24, Surabaya 9, Medan 8)
Temuan        : \PDFSuite Updater di SBY-WS-0107; T1053.005 + dugaan T1574.001
Jinak         : 4 pasangan (updater aplikasi rapat, skrip inventaris IT, 2 aplikasi pribadi -> IT)
Pelajaran     : IOC INC-2026-026 buta terhadap host di luar kantor (split tunnel), varian C2 baru,
                dan host tanpa MDE/Sysmon/4698; pola persistence di disk tidak
Celah data    : JAB-WS-Audit belum ditautkan ke OU POP dan Bandung (4698) -> Agung (ulangan Day 04)
Deteksi       : Hunt -013 dijadwalkan ulang mingguan di Velociraptor (bukan rule SIEM, karena
                datanya tidak ada di SIEM); usulan rule ke Sari setelah 4698 tersedia
```

Hipotesis turunan yang masuk backlog (tanpa nomor, karena nomor hunt baru dibagikan saat dijadwalkan):

- Laptop yang jarang berada di kantor menjalankan installer dari internet saat di luar kantor (split tunnel) dan memasang persistence di profil pengguna, apa pun nama aplikasinya. Data: prefetch dan file task lintas fleet, dicocokkan dengan hari tanpa sesi VPN. Ini bukan scoping `INC-2027-040`, yang mencari varian PDFSuite saja; hipotesis ini mencari pola yang sama dengan umpan lain.
- DLL bernama DLL sistem (`version.dll` dan sejenisnya) di samping executable bertanda tangan di folder yang bisa ditulis pengguna (T1574.001), dengan `JAB DocSync` di `Program Files` sebagai pengecualian yang diketahui.
- Cakupan: 64 workstation yang belum terjangkau, terutama 17 di POP, untuk diulang setelah terdaftar atau lewat offline collector (bagian 1.7).

Jawaban untuk Dimas, dikirim Kamis 17:00. Setiap baris merujuk subbagian di atas supaya bisa dipakai saat Hendra bertanya.

| Pertanyaan Dimas | Jawaban singkat | Dasar |
|---|---|---|
| Apa yang dilihat Velo, tidak dilihat Splunk | Keadaan mesin sekarang: file task, autostart, file di profil, prefetch, cache DNS, termasuk di 229 workstation tanpa Sysmon | Bagian 1.1, 2.5 |
| Risiko memasang agent ke semua host | Server setara tier-0 (bisa menjalankan apa saja di semua host); dikendalikan dengan jaringan, peran, patch, dan default tanpa upload; limits bukan batas keamanan | Bagian 1.3 |
| Hunt tanpa membebani | Canary dulu, timeout dan batas baris/upload di setiap hunt, keluaran kecil; CPU limit tidak berlaku untuk tool eksternal | Bagian 1.5, 2.2 |
| Artifact persistence | `Windows.Sysinternals.Autoruns` untuk gambaran luas, `Windows.System.TaskScheduler` untuk task, `Windows.Sys.StartupItems` sebagai cadangan ringan | Bagian 1.2, 2.3, 2.4 |
| Laptop jarang online | Hanya terjangkau saat VPN tersambung; expiry satu minggu, laporan menulis cakupan; offline collector untuk sisanya; frontend tidak dibuka ke internet | Bagian 1.7, 2.1 |
| Monitoring real-time | Belum ke seluruh fleet; pilot dua minggu di 23 workstation POP tanpa telemetri | Bagian 1.8, 2.9 |
| Kapan cukup Splunk | Pertanyaan historis atau lintas sumber dengan data yang ada; beralih ke endpoint saat Splunk menjawab "datanya tidak ada" | Bagian 1.9 |

**Kapan gagal:** laporan `-013` hanya menulis "ditemukan, diserahkan ke IR" tanpa cakupan; minggu depan tidak ada yang tahu bahwa 64 workstation, termasuk 17 di POP tempat temuan ini berasal, belum pernah diperiksa.

## 3. Lab praktik (di VM lab terisolasi)

**Prasyarat:** server Velociraptor lab dengan client di VM Windows dan Linux lab (dipasang oleh kamu sendiri dari rilis resmi 0.77.3); snapshot VM. Jangan memakai data, nama, atau kejadian dari pekerjaan nyata; PT JAB hanya contoh fiktif.

1. **Kenali UI.** Di server, telusuri daftar artifact bawaan. Catat lima artifact yang relevan untuk hunting persistence dan eksekusi, beserta parameter dan nama kolom keluarannya.
2. **Cakupan.** Jalankan query `clients()` dari bagian 2.1 di notebook server. Catat client yang terdaftar, waktu terakhir terlihat, dan label. Beri satu VM label `velo-canary`.
3. **Hunt pertama dengan canary.** Buat hunt `Windows.Sysinternals.Autoruns` (bagian 2.2) ke label `velo-canary` saja, dengan kategori dipilih manual dan timeout diisi. Catat durasi dan pemakaian CPU di VM selama `autorunsc` berjalan. Lalu buat hunt kedua ke semua client Windows yang mengecualikan label canary.
4. **Stacking autoruns.** Tunggu hasil, catat header kolom yang sebenarnya, sesuaikan query stacking (bagian 2.3), lalu jalankan di notebook. Catat entri yang hanya di sedikit host. Ulangi dengan `Windows.Sys.StartupItems` dan bandingkan cakupannya.
5. **Scheduled task.** Jalankan hunt scheduled task (bagian 2.4), lalu kedua query-nya. Uji `regex_replace()` dan `enumerate()` di versi-mu. Bandingkan dengan apa yang terlihat di log Wazuh/Splunk untuk host yang sama; catat task yang terlihat di endpoint tetapi tidak di log.
6. **Batas sumber daya.** Jalankan collection `Windows.Search.FileFinder` atas `C:\Users\*\**` dengan `Calculate_Hash` aktif dua kali: tanpa batas, lalu dengan `ops_per_second` 20 dan `max_rows` kecil. Catat durasi, CPU, dan apakah collection dibatalkan saat `max_rows` tercapai. Ulangi `Windows.Sysinternals.Autoruns` dengan `cpu_limit` rendah dan amati bahwa `autorunsc` tidak ikut dibatasi.
7. **Pencarian file.** Sesuaikan artifact pencarian file (bagian 2.7) untuk mencari executable di Temp. Hash hasilnya.
8. **SIEM lalu endpoint.** Ambil satu host yang ditandai hunt SIEM (Day 06/08), lalu kumpulkan artifact endpoint dari host itu (bagian 1.9). Tulis apa yang log tidak tunjukkan tetapi endpoint tunjukkan.
9. **Buktikan menangkap target.** Di VM lab dengan snapshot, buat dua persistence jinak: satu value di `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` yang menunjuk ke `notepad.exe` (T1547.001 [S11]) dan satu scheduled task harian yang menjalankan `notepad.exe` (T1053.005 [S7]). Untuk meniru pola bagian 2.5 secara jinak, buat juga satu task saat logon yang menjalankan salinan `notepad.exe` dari folder `%LOCALAPPDATA%\LabTest\`. Jalankan ulang hunt. Yang harus terlihat: value Run muncul di `Windows.Sys.StartupItems` dan autoruns (kategori Logon), task muncul di `Windows.System.TaskScheduler` dengan `Command` berakhiran `notepad.exe` dan `UserId` akunmu, dan task ketiga muncul di query stacking bagian 2.4 dengan `hosts` 1. Kembalikan snapshot.
10. **Host offline.** Matikan satu VM client, buat hunt baru dengan expiry pendek, lalu nyalakan VM sebelum dan sesudah expiry di dua percobaan. Catat kapan VM menerima hunt dan kapan tidak.
11. **Offline collector.** Buat offline collector berisi `Windows.System.TaskScheduler` dan `Windows.Sys.StartupItems` dengan enkripsi X.509. Jalankan di VM Windows yang client-nya dihentikan, lalu impor container-nya ke server dan baca hasilnya di notebook.
12. **Laporan.** Isi laporan hunt (Day 07) dengan temuan endpoint, angka cakupan per kelompok VM, dan handover.

**Hasil yang sebaiknya tersimpan:**

- Lima artifact hunting dicatat.
- Daftar client dan label, plus angka cakupan saat hunt.
- Hunt autoruns dijalankan lewat canary dan di-stacking di notebook, dengan durasi dan CPU tercatat.
- Task yang terlihat di endpoint tetapi tidak di log dicatat.
- Catatan perbandingan batas sumber daya, termasuk bukti bahwa `autorunsc` tidak dibatasi CPU limit.
- Pencarian file menghasilkan hash untuk dicocokkan.
- Satu host SIEM diperdalam dengan artifact endpoint.
- Hunt menangkap tiga persistence jinak uji.
- Catatan perilaku expiry untuk client offline.
- Container offline collector yang berhasil diimpor.
- Laporan hunt tersimpan.

**Variasi tantangan:** pasang satu artifact client monitoring yang menerapkan sebuah rule Sigma `process_creation` sederhana (misalnya `Image|endswith: '\\whoami.exe'`) di VM Windows, atau kumpulkan `Windows.Sigma.EventLogs` dengan rule itu sebagai pembanding. Jalankan aktivitas jinak yang cocok dengan rule itu dan pastikan event real-time muncul di server. Bandingkan dengan snapshot hunt: perilaku mana yang hanya tertangkap monitoring, bukan snapshot, dan kenapa. Untuk VM tanpa Sysmon, ulangi dengan `Windows.Events.ProcessCreation` dan catat proses berumur pendek mana yang terlewat.

## 4. Troubleshooting

Tabel ini memuat masalah yang sering muncul saat hunt endpoint pertama. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Hunt tidak menghasilkan apa-apa | Hunt masih `Paused`; client offline; kondisi hunt terlalu sempit | Start hunt; cek status client; longgarkan kondisi OS/label |
| Artifact tidak ditemukan | Nama artifact beda di versi (misalnya menulis `Windows.Sys.Autoruns`) | Cari kata kunci di daftar artifact UI; pakai `Windows.Sysinternals.Autoruns` |
| Autoruns gagal atau kosong | Binary `autorunsc` tidak tersedia di server; izin `EXECVE` tidak ada | Cek tool `Autorun_amd64` di server; unggah binary manual di lab offline |
| Autoruns dibatalkan di sebagian host | Timeout default 600 detik terlalu pendek untuk laptop lambat | Naikkan timeout untuk hunt itu; catat host yang dibatalkan di cakupan |
| Laptop melambat saat hunt autoruns walau CPU limit diisi | CPU limit tidak berlaku untuk program eksternal via `execve()` | Canary, timeout, dan jadwal di luar jam sibuk |
| Collection berhenti di tengah | `max_rows` atau `max_upload_bytes` tercapai | Periksa log collection; perbesar batas atau persempit artifact |
| `source()` kosong untuk TaskScheduler | Nama source tidak disebut | Pakai `Windows.System.TaskScheduler/Analysis` |
| VQL error di notebook | Nama kolom/fungsi beda versi | Lihat skema hasil; sesuaikan nama kolom |
| Stacking memberi angka host terlalu besar | `count()` menghitung baris, bukan host | Pakai dua tahap: `GROUP BY` per host dulu |
| Regex path tidak cocok | Escaping backslash | Pakai string mentah `'''...'''` atau `.` sebagai pengganti backslash; ingat `Command` di TaskScheduler sudah huruf kecil dan `=~` tidak peka huruf secara default |
| Hasil hunt lambat masuk | Client offline atau fleet besar | Tunggu; hunt mengeksekusi saat client kembali online sampai expiry |
| Laptop di luar kantor tidak pernah terdaftar | VPN tidak tersambung sejak paket dibagikan; split tunnel tidak membawa subnet server | Cek rute split tunnel ke `10.20.1.31`; cek log VPN; rencanakan offline collector |
| Monitoring Sigma tidak memicu | Rule atau sumber event belum terpasang; `logsource` rule tidak terpetakan | Cek artifact event aktif di client dan `logsource` rule (misalnya `process_creation/windows` butuh log Sysmon) |
| Event monitoring terlambat beberapa menit | Batching default sampai sekitar 120 detik; client offline memakai buffer lokal | Normal; jangan dipakai untuk respons detik |

## 5. Kesalahan umum dan jebakan

- **Mengira log SIEM memuat semua artefak endpoint.** Registry mentah, prefetch, file task, dan file di disk sering tidak dikirim; Velociraptor menjangkaunya.
- **Menulis "seluruh fleet diperiksa".** Hunt kedaluwarsa, bukan selesai; tulis berapa host yang menjawab sampai jam tertentu dan siapa yang tidak (bagian 1.4).
- **Memperlakukan server Velociraptor seperti server monitoring biasa.** Server yang bisa menjalankan program di semua endpoint adalah aset tier-0 (bagian 1.3).
- **Menganggap resource limits sebagai pengaman.** Limits tidak berlaku untuk tool eksternal dan bisa diabaikan client yang sudah dikuasai [S14].
- **Menulis VQL dari nol** padahal artifact bawaan sudah ada; salin dan sesuaikan.
- **Menjalankan hunt berat ke seluruh fleet tanpa batas** sehingga membebani endpoint; batasi dengan kondisi, parameter, canary, dan timeout.
- **Menyaring dengan "tidak bertanda tangan" saja.** Side-loading memakai executable bertanda tangan sah; yang tidak bertanda tangan adalah DLL di sampingnya (bagian 2.5).
- **Berhenti di pencarian IOC.** Varian dengan domain dan hash baru lolos dari daftar IOC; pola persistence di disk tetap terlihat (bagian 2.6).
- **Melanjutkan sendiri setelah temuan kuat.** Membunuh proses, membuat dump, atau mengisolasi host adalah keputusan IR (bagian 2.8).
- **Menyamakan hunt (snapshot) dengan monitoring (aliran).** Perilaku sesaat butuh monitoring.
- **Lupa snapshot VM** saat menguji persistence jinak.
- `[komunitas, belum terkonfirmasi]` Velociraptor banyak dipakai sebagai pengganti EDR open-source untuk hunting dan DFIR lintas fleet; nama artifact dan fungsi VQL berubah antar versi, jadi selalu cek di versi yang terpasang [S2].

## 6. Catatan terkini

Bagian ini menampung detail versi, perubahan nama, dan hal yang perlu dicek ulang saat versi berganti. Isinya tidak mengubah alur kerja di bagian 1 dan 2.

- Velociraptor 0.77.3 (5 Oktober 2026) adalah rilis perbaikan yang menutup beberapa CVE; perbarui ke versi ini [S1]. Ia menambah `Azure.Monitor.Upload` dan memperbaiki `Windows.Forensics.Prefetch` serta parsing registry [S1]. Per 18 Oktober 2026, 0.77.3 masih rilis terbaru di halaman rilis [S1].
- Dua artifact backup kini mengeluarkan lebih sedikit kolom, sehingga query yang membaca kolom yang dihapus perlu diperbarui [S1]; ini contoh kenapa nama kolom VQL perlu dicek. Rilis yang sama juga mengubah `enrollments_per_second: -1` menjadi menonaktifkan enrollment, dan glob dengan alternatif tidak seimbang kini menghasilkan error [S1].
- Client monitoring mendukung ETW (Windows), eBPF (Linux), dan rule Sigma [S2], sehingga rule deteksi yang sama bisa dipakai di endpoint dan di SIEM. Sejak 0.74, Sigma di Velociraptor dipakai di luar Windows event log, termasuk event real-time ETW dan eBPF [S18].
- Artifact autoruns di referensi saat ini bernama `Windows.Sysinternals.Autoruns` [S4]; nama `Windows.Sys.Autoruns` tidak ada di referensi.
- Operator `=~` tidak peka huruf besar/kecil secara default [S3]; contoh VQL lama yang menulis `(?i)` tetap berjalan.
- ATT&CK v20: T1574.001 bernama "DLL" (Hijack Execution Flow: DLL), mencakup side-loading, search order hijacking, dan phantom DLL, dengan taktik Stealth dan Execution [S20]; daftar sub-teknik T1574 di v20 tidak lagi memuat T1574.002 [S21]. Dokumentasi, rule, dan laporan lama masih memakai "T1574.002 DLL Side-Loading" dan "T1574.001 DLL Search Order Hijacking", jadi kenali keduanya saat memetakan.
- ATT&CK T1053.005 (v20, versi 1.8) menyebut task tersembunyi yang dibuat dengan menghapus nilai Security Descriptor di registry, yang membuatnya tidak terlihat di `schtasks /query` dan tampilan Task Scheduler [S7]. Apakah task seperti itu masih meninggalkan file XML yang dibaca `Windows.System.TaskScheduler` perlu diuji di lab sebelum hasil hunt dianggap mencakupnya.
- Halaman `Server.Import.CuratedSigma` di referensi artifact tidak bisa dibuka saat Day ini ditulis; artifact itu masih dirujuk dari halaman `Windows.Sigma.EventLogs` [S10]. Cek keberadaannya di daftar artifact server.
- Day 10-13 memakai artifact dan log ini untuk berburu teknik ATT&CK spesifik.

## 7. Cheat sheet

```
KONSEP     client (agent) | server | VQL | artifact (query terkemas) | hunt (artifact ke banyak endpoint) | client monitoring | notebook
ARAH       client selalu memulai koneksi ke frontend (port 8000); laptop luar kantor hanya terjangkau via VPN
HUNT       pilih artifact -> atur parameter/kondisi (label, OS) -> Start (default Paused) -> client online menjawab
           -> tinjau & stacking di notebook ; expiry default 1 minggu ; cakupan dibekukan pada jam tertentu
BEBAN      canary label dulu ; timeout (default 600 s), max_rows, max_upload_bytes ; ops_per_second 20-50 utk scan isi
           cpu_limit/iops_limit TIDAK berlaku utk execve (autorunsc) ; limits bukan batas keamanan
RISIKO     server = tier-0 ; artifact_writer ~ domain admin di endpoint ; EXECVE ; patch (0.77.3) ; privasi -> DPO
VQL        SELECT kol FROM plugin(args) WHERE kondisi ; =~ regex (tidak peka huruf) ; '''raw''' ; `kolom berspasi`
STACKING   VQL tanpa distinct count: GROUP BY ClientId+entri dulu, lalu count() per entri ; filter agregat di luar
ARTEFAK    Windows.Sysinternals.Autoruns (autorunsc, butuh EXECVE) | Windows.Sys.StartupItems (Run key + Startup)
           Windows.System.TaskScheduler/Analysis (XML task) | Windows.Search.FileFinder (glob+hash+YARA)
           Windows.Forensics.Prefetch, Windows.Forensics.Amcache (eksekusi) | Windows.System.DNSCache
           Windows.Network.NetstatEnriched (EXECVE; jangan centang KillProcess/DumpProcess)
TERARAH    read-only: salin task XML, file + hash, prefetch, DNS cache, netstat ; JANGAN jalankan/buka/hapus
OFFLINE    expiry hunt | buffer lokal monitoring | offline collector (ZIP, X.509, impor ke server)
MONITORING real-time ETW/eBPF + Sigma ; untuk perilaku sesaat yang terlewat snapshot ; batching ~120 s
VS SIEM    SIEM: log terkirim, historis, korelasi | Velo: artefak live endpoint, verifikasi, triage fleet
POLA       SIEM menandai host -> Velociraptor memperdalam artefak host itu -> hash/YARA -> handover
           Velo menemukan indikator baru -> cari di SIEM (dns, vpn, proxy) -> sejak kapan, host mana lagi
ESKALASI   persistence aktif / C2 terbuka -> kabari IC sekarang, kumpulkan read-only paralel, jangan tunggu laporan
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Semua client yang online sudah mengirim hasil `HUNT-2027-013`, jadi laporan boleh menulis bahwa scheduled task di seluruh fleet PT JAB sudah diperiksa." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Hunt Velociraptor tidak selesai, melainkan kedaluwarsa, dan hanya client yang terhubung selama hunt aktif yang menjawab. Sampai Kamis 16:00, 379 dari 443 host Windows menjawab; 64 workstation tidak terjangkau, 38 di antaranya bahkan belum terdaftar, dan 17 berada di POP, lokasi temuan hari itu. Laporan harus membekukan angka cakupan pada jam tertentu dan menulis siapa yang tidak terjangkau. Lihat bagian 1.4, 2.1, dan 2.10.

</details>

**2. Skenario keputusan.** Pukul 11:05 kamu melihat `\PDFSuite Updater` di `SBY-WS-0107`, yang sedang tersambung VPN dari rumah. Langkah mana yang paling tepat?

- A. Selesaikan dulu tinjauan semua pasangan dan tulis laporan lengkap, lalu kirim ke Dimas sore hari supaya temuannya utuh.
- B. Jalankan pengumpulan terarah read-only ke host itu (file task, isi folder dan hash, prefetch, cache DNS, koneksi aktif) dan kabari Dimas saat itu juga, tanpa menjalankan, membuka, atau menghapus apa pun.
- C. Jalankan `NetstatEnriched` dengan `KillProcess` dicentang dan `Windows.Remediation.Quarantine` supaya koneksi C2 langsung terputus.

<details><summary>Jawaban</summary>

B. Persistence aktif dengan koneksi C2 terbuka tidak menunggu laporan, dan laptop bisa terputus kapan saja sehingga bukti volatil perlu diambil sekarang tanpa mengubah keadaan host. A keliru karena laptop terputus pukul 11:58 dan keputusan IR tertunda berjam-jam. C keliru karena membunuh proses dan mengisolasi host adalah keputusan containment milik IR dan IC, bukan langkah hunt; opsi `KillProcess` juga berlaku ke semua baris yang cocok tanpa pengaman. Lihat bagian 2.7 dan 2.8.

</details>

**3. Pertanyaan jebakan.** "Hunt `Windows.Sysinternals.Autoruns` diberi `cpu_limit` 20%, jadi laptop pengguna dijamin tidak terasa lambat." Benarkah?

<details><summary>Jawaban</summary>

Tidak. CPU limit dan IOPS limit tidak berlaku untuk program eksternal yang dijalankan lewat `execve()`, dan artifact autoruns justru menjalankan `autorunsc`. Rem yang bekerja adalah canary dulu, timeout, jumlah host yang menjalankan bersamaan, dan jadwal. Selain itu, resource limits ditegakkan client pada dirinya sendiri dan bukan batas keamanan. Lihat bagian 1.5 dan 2.2.

</details>

**4. Skenario keputusan.** Rudi bertanya bagaimana menjangkau 17 workstation POP yang belum terjangkau hunt minggu ini. Pilihan mana yang paling tepat?

- A. Buka frontend `jkt-velo02` ke internet lewat DMZ supaya laptop bisa terhubung tanpa VPN.
- B. Biarkan hunt aktif sampai expiry, minta manajer POP memastikan laptop tersambung VPN atau dibawa ke kantor, dan siapkan offline collector X.509 untuk yang tetap tidak tersambung; tulis yang tersisa di cakupan.
- C. Anggap aman karena 6 workstation POP yang terjangkau tidak menunjukkan apa pun selain `SBY-WS-0107`.

<details><summary>Jawaban</summary>

B. Expiry memberi waktu bagi laptop yang sesekali tersambung, offline collector menjangkau host yang tidak bisa mencapai server, dan sisa yang tidak terjangkau ditulis sebagai di luar cakupan. A keliru karena server tier-0 yang menghadap internet memperluas permukaan serangan, dan rilis keamanan tahun ini menunjukkan server memang punya kerentanan; keputusan PT JAB adalah menerima ketergantungan pada VPN. C keliru karena host yang tidak menjawab tidak bisa disebut bersih, apalagi di lokasi tempat temuan berasal. Lihat bagian 1.7 dan 2.10.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Hendra Wijaya, dalam tiga kalimat, kenapa daftar IOC `INC-2026-026` tidak menemukan `SBY-WS-0107` tetapi `HUNT-2027-013` menemukannya.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Daftar IOC Desember mencari domain, IP, dan hash yang kita lihat di dua laptop waktu itu, sedangkan laptop Surabaya ini menjalankan installer dari rumah tanpa VPN, terhubung ke domain dan IP yang berbeda, dan tidak punya Defender maupun Sysmon, jadi tidak ada satu pun lapis pencarian kita yang bisa melihatnya. Hunt hari Kamis tidak mencari indikator, tetapi membaca langsung daftar scheduled task di disk 379 komputer dan mencari pola yang langka: task yang hanya ada di satu laptop dan menjalankan program dari folder profil pengguna. Penyerang bisa mengganti domain dan hash dengan murah, tetapi cara mereka bertahan di komputer jauh lebih jarang berubah, dan itulah yang kita cari."

Kesalahan yang sering muncul:
- Menyalahkan tim IR Desember, padahal scoping saat itu benar untuk indikator dan telemetri yang ada.
- Lupa menyebut split tunnel, alasan trafik dari rumah tidak pernah terlihat di proxy dan DNS.
- Menyebut hunt "memindai seluruh perusahaan", padahal cakupannya 379 dari 443 host.

</details>

**6. Pertanyaan jebakan.** "Untuk tahu berapa host yang punya setiap image path autostart, cukup `SELECT ImagePath, count() AS hosts FROM source(...) GROUP BY ImagePath`." Benarkah?

<details><summary>Jawaban</summary>

Tidak. `count()` menghitung baris di setiap bin, bukan host, dan satu host bisa memiliki beberapa baris untuk image path yang sama (misalnya entri di beberapa profil pengguna). VQL tidak punya distinct count, jadi rapatkan dulu ke satu baris per pasangan host dan entri dengan `GROUP BY` atas kunci gabungan, lalu hitung per entri di tahap kedua. Lihat bagian 1.6 dan 2.3.

</details>

**7. Interview question (English).** "When would you pivot from your SIEM to an endpoint tool like Velociraptor during a hunt, and what risks do you consider before deploying such a tool fleet-wide?"

<details><summary>Sample answer</summary>

"I start in the SIEM whenever the question is historical or needs several sources, because it doesn't touch endpoints and doesn't need hosts to be online. I pivot to the endpoint when the SIEM tells me the data doesn't exist: artefacts that are never logged, like scheduled task files, autoruns or prefetch, or hosts without Sysmon or EDR. In one hunt, stacking scheduled task names and action paths across about 380 hosts surfaced a single laptop with a logon task running a signed binary from AppData next to an unsigned DLL; the IOC list from an earlier incident had missed it because the C2 domain was new and the laptop was used off-network on split-tunnel VPN. I collected read-only evidence while it was still online and escalated to IR immediately rather than finishing the report. Before deploying fleet-wide, I treat the server as tier-0, since anyone who controls it can run code on every endpoint: restricted network access, least-privilege roles, prompt patching, no file uploads by default, a privacy agreement with the DPO, and a canary label with timeouts for every heavy hunt. I also report coverage honestly, because a hunt only covers the clients that checked in before it expired."

What makes this answer strong: it gives a clear rule for when to use each tool, backs it with a concrete hunt that shows why patterns beat indicators, separates the hunter's role from IR's, and treats both operational load and the tool's own attack surface as real risks.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Velociraptor releases (0.77.3) | https://github.com/Velocidex/velociraptor/releases | primer | 0.77.3, 2026-10-05; diakses 2026-10-08, dicek ulang 2026-10-18 | Tinggi. Versi, CVE, perubahan artifact, perubahan yang memutus kompatibilitas |
| S2 | Velociraptor documentation: Overview | https://docs.velociraptor.app/docs/overview/ | primer | diakses 2026-10-10, dicek ulang 2026-10-18 | Tinggi. Client, VQL, artifact, hunt, monitoring, notebook, offline collector; koneksi persisten dari client |
| S3 | Velociraptor documentation: VQL fundamentals | https://docs.velociraptor.app/docs/vql/fundamentals/ | primer | diakses 2026-10-10, dicek ulang 2026-10-18 | Tinggi. GROUP BY, fungsi agregat (count, sum, enumerate), LET, `=~` (RE2, tidak peka huruf), backtick |
| S4 | Velociraptor artifact reference: Windows.Sysinternals.Autoruns | https://docs.velociraptor.app/artifact_references/pages/windows.sysinternals.autoruns/ | primer | diakses 2026-10-10, dicek ulang 2026-10-18 | Tinggi. FetchBinary, parameter, EXECVE, parse CSV; nama kolom tidak dirinci |
| S5 | Velociraptor artifact reference: Windows.Sys.StartupItems | https://docs.velociraptor.app/artifact_references/pages/windows.sys.startupitems/ | primer | diakses 2026-10-10, dicek ulang 2026-10-18 | Tinggi. Run key, StartupApproved, folder Startup, kolom keluaran |
| S6 | Velociraptor artifact reference: Windows.System.TaskScheduler | https://docs.velociraptor.app/artifact_references/pages/windows.system.taskscheduler/ | primer | diakses 2026-10-10, dicek ulang 2026-10-18 | Tinggi. Source Analysis, parameter, kolom keluaran, normalisasi `Command` |
| S7 | MITRE ATT&CK: T1053.005 Scheduled Task | https://attack.mitre.org/techniques/T1053/005/ | primer | ATT&CK v20 (versi 1.8, diubah 2026-05-12); diakses 2026-10-10, dicek ulang 2026-10-18 | Tinggi. Taktik, cara pembuatan task, task tersembunyi |
| S8 | Velociraptor artifact reference: Windows.Search.FileFinder | https://docs.velociraptor.app/artifact_references/pages/windows.search.filefinder/ | primer | diakses 2026-10-10, dicek ulang 2026-10-18 | Tinggi. Parameter glob, accessor, YARA, hash, rate limit, kolom keluaran |
| S9 | Velociraptor artifact reference: Windows.Events.ProcessCreation | https://docs.velociraptor.app/artifact_references/pages/windows.events.processcreation/ | primer | diakses 2026-10-10 | Tinggi. CLIENT_EVENT via WMI |
| S10 | Velociraptor artifact reference: Windows.Sigma.EventLogs | https://docs.velociraptor.app/artifact_references/pages/windows.sigma.eventlogs/ | primer | diakses 2026-10-10, dicek ulang 2026-10-18 | Tinggi. Sigma atas EVTX, artifact demonstrasi, rujukan Server.Import.CuratedSigma |
| S11 | MITRE ATT&CK: T1547.001 Registry Run Keys / Startup Folder | https://attack.mitre.org/techniques/T1547/001/ | primer | diakses 2026-10-10 | Tinggi |
| S12 | Velociraptor documentation: Hunting | https://docs.velociraptor.app/docs/hunting/ | primer | diakses 2026-10-18 | Tinggi. Hunt manager, Paused, expiry default 1 minggu, label, client offline, volume data, notebook, `hunt_results()` |
| S13 | Velociraptor documentation: Client monitoring | https://docs.velociraptor.app/docs/clients/monitoring/ | primer | diakses 2026-10-18 | Tinggi. CLIENT_EVENT, label group, writeback, `Client.local_buffer`, batching 120 detik, event server |
| S14 | Velociraptor documentation: Limiting resource usage | https://docs.velociraptor.app/docs/artifacts/resources/ | primer | diakses 2026-10-18 | Tinggi. Kunci dan default resource limits, urutan prioritas, execve tidak dibatasi, bukan batas keamanan |
| S15 | Velociraptor documentation: Offline collections | https://docs.velociraptor.app/docs/deployment/offline_collections/ | primer | diakses 2026-10-18 | Tinggi. Binary dengan artifact tertanam, container ZIP, enkripsi X.509, impor, kapan dipakai |
| S16 | Velociraptor documentation: Deployment | https://docs.velociraptor.app/docs/deployment/ | primer | diakses 2026-10-18 | Tinggi. URL server di client, port frontend 8000 dan GUI 8889, MSI, default buffer lokal 50 MB/1 GB |
| S17 | Velociraptor blog: Velociraptor's ACL model | https://docs.velociraptor.app/blog/2020/2020-03-29-velociraptors-acl-model-7f497575daee/ | primer (blog proyek) | 2020-03-29; diakses 2026-10-18 | Sedang-tinggi. Peran dan izin EXECVE; tulisan lama, cek model izin di versi terpasang |
| S18 | Velociraptor blog: Developing Sigma Rules in Velociraptor | https://docs.velociraptor.app/blog/2025/2025-02-02-sigma/ | primer (blog proyek) | 2025-02 (dari URL); diakses 2026-10-18 | Tinggi. Model Sigma, Windows.Sigma.Base, model real-time ETW/eBPF |
| S19 | Velociraptor Sigma Project | https://sigma.velocidex.com/ | primer (proyek terkait) | diakses 2026-10-18 | Sedang-tinggi. Daftar model dan artifact; pembagian triage/monitoring disimpulkan dari nama |
| S20 | MITRE ATT&CK: T1574.001 Hijack Execution Flow: DLL | https://attack.mitre.org/techniques/T1574/001/ | primer | ATT&CK v20 (versi 3.0, diubah 2026-09-11); diakses 2026-10-18 | Tinggi. Side-loading, search order hijacking, phantom DLL; taktik Stealth dan Execution |
| S21 | MITRE ATT&CK: T1574 Hijack Execution Flow | https://attack.mitre.org/techniques/T1574/ | primer | ATT&CK v20; diakses 2026-10-18 | Tinggi. Daftar sub-teknik v20 tanpa T1574.002 |
| S22 | Velociraptor artifact reference: Windows.Forensics.Prefetch | https://docs.velociraptor.app/artifact_references/pages/windows.forensics.prefetch/ | primer | diakses 2026-10-18 | Tinggi. Parameter, kolom, delapan waktu eksekusi terakhir di Windows 10 |
| S23 | Velociraptor artifact reference: Windows.System.DNSCache | https://docs.velociraptor.app/artifact_references/pages/windows.system.dnscache/ | primer | diakses 2026-10-18 | Tinggi. WMI MSFT_DNSClientCache, kolom keluaran |
| S24 | Velociraptor artifact reference: Windows.Network.NetstatEnriched | https://docs.velociraptor.app/artifact_references/pages/windows.network.netstatenriched/ | primer | diakses 2026-10-18 | Tinggi. Filter, kolom, EXECVE, opsi KillProcess dan DumpProcess tanpa pengaman |
| S25 | Velociraptor artifact reference: Windows.Remediation.Quarantine | https://docs.velociraptor.app/artifact_references/pages/windows.remediation.quarantine/ | primer | diakses 2026-10-18 | Tinggi. Karantina IPsec, pengecualian DNS/DHCP/server, izin EXECVE dan NETWORK |

**Catatan sumber:** nama kolom keluaran `Windows.Sysinternals.Autoruns` mengikuti header CSV `autorunsc` dan tidak dirinci di referensi artifact; daftar di bagian 2.3, termasuk bentuk nilai kolom `Signer`, perlu dicocokkan dengan hasil hunt di lab. Sintaks backtick untuk kolom berspasi sudah dikonfirmasi [S3]; `format()`, `regex_replace()`, `enumerate(items=...)`, plugin `clients()`, dan satuan `last_seen_at` di query bagian 2.1 dan 2.4 perlu diuji di notebook lab. Default `max_rows`, `max_upload_bytes`, `cpu_limit`, `iops_limit`, dan `ops_per_second` tidak disebut di [S14]. Model peran dan izin [S17] berasal dari 2020; cek apakah versi terpasang mengizinkan `EXECVE` diberikan ke peran selain administrator. Pembagian artifact Sigma menjadi triage dan monitoring [S19] disimpulkan dari nama artifact. Halaman `Server.Import.CuratedSigma` tidak bisa dibuka saat Day ini ditulis. Perilaku task tersembunyi terhadap file XML belum diuji. Seluruh isi `HUNT-2027-012`, `HUNT-2027-013`, angka cakupan, host, akun, hash, dan `INC-2027-040` adalah penerapan catatan ini pada organisasi fiktif, bukan hasil eksekusi nyata.
