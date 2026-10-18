---
day: 18
title: 'Hunting dengan notebook: kapan notebook dan kapan SIEM, notebook yang bisa diulang dan diaudit, pandas, MSTICPy, dan higiene data'
researched_on: 2026-10-18
versions_checked: 'MSTICPy 3.1.0 (rilis GitHub 2026-09-21; Python 3.10 sampai 3.14; requirements repo membatasi pandas di bawah 3.0; dokumentasi Splunk provider, TIProviders, IoCExtract, Pivot functions, Velociraptor provider; sumber splunk_driver.py dan tilookup.py); pandas 3.0.6 (2026-09-17) dan 2.3.3 (2025-09-29; to_datetime, merge, groupby diff, drop_duplicates, catatan rilis 3.0.0); JupyterLab 4.6.4 (2026-09-21); papermill (parameterize); nbstripout; nbconvert (config options); Splunk Enterprise 10.6 Search Manual (export lewat REST), REST API tutorial 10.2, autentikasi token 10.4; Velociraptor 0.77.3 (server API, hunt_results, client_info); MITRE ATT&CK v20 (T1053.005 v1.8, T1547.001 v2.1, T1071.001 v1.5)'
---

# Day 18: Hunting dengan notebook (Jupyter, pandas, MSTICPy, dan higiene data)

Cakupan: kapan sebuah hunt lebih murah dikerjakan di notebook daripada di SIEM, cara menyusun notebook hunt yang bisa diulang dan diaudit, lima operasi pandas yang menutup sebagian besar kebutuhan hunting, apa yang diberikan MSTICPy, lingkungan dan aturan menyimpan data ekspor, jebakan zona waktu dan duplikasi, serta cara hasil notebook kembali ke repo hunt.

## Ide inti

SIEM dirancang untuk mencari dan mengagregasi di atas data besar, dan untuk itu ia sulit dikalahkan. Ada kelas hunt yang membuatnya terasa sempit: menggabungkan sumber yang skemanya berbeda (hasil koleksi endpoint, log firewall, daftar aset), menghitung statistik yang tidak disediakan bahasa query-nya, atau mencoba belasan ambang pada data yang sama. Di SIEM, setiap percobaan berarti menjalankan ulang search yang sama atas data yang sama di infrastruktur yang dipakai bersama. Notebook membalik urutannya: data dipersempit di SIEM, ditarik sekali, lalu semua iterasi terjadi di memori mesin analisis. Yang ditawarkan notebook bukan kecepatan, melainkan tiga hal lain: kebebasan bentuk analisis, catatan langkah yang menyatu dengan hasilnya, dan kemampuan menjalankan ulang analisis yang sama bulan depan dengan satu perubahan parameter.

Harga dari kebebasan itu adalah tanggung jawab yang tadinya dipegang SIEM. Splunk menyimpan data dengan retensi, hak akses, dan zona waktu yang jelas; begitu data diekspor ke notebook, semua itu menjadi urusanmu. Salinan data bisa hidup lebih lama dari sumbernya, keluaran sel yang memuat nama pengguna ikut tersimpan di file notebook, dan dua sumber dengan zona waktu berbeda bisa digabung tanpa satu pesan error pun. Notebook hunt yang baik karena itu punya dua sisi yang sama pentingnya: analisis yang bisa diulang (parameter di satu tempat, normalisasi yang gagal keras, jumlah baris yang dicek di setiap langkah) dan data yang dikelola (lokasi, akses, retensi, dan apa yang kembali ke repo).

Kamu sudah mengenal pola ini dari NOC. Saat gangguan intermiten di satu POP butuh analisis yang tidak bisa dilakukan NMS, engineer menarik ekspor NetFlow dan syslog router untuk rentang tertentu sekali ke laptop analisis, lalu mengolahnya di skrip: menggabungkan dengan daftar perangkat, menghitung interval, mencoba beberapa ambang. NMS tidak ditembak berulang-ulang untuk setiap percobaan, dan langkah analisisnya tersimpan di skrip yang sama dengan hasilnya. Batas analoginya ada dua. Pertama, ekspor log keamanan berisi data pribadi karyawan (akun, host, kebiasaan kerja), sehingga salinannya harus dikelola lokasi, akses, dan retensinya seperti data aslinya, bukan dibiarkan di folder Downloads. Kedua, NOC jarang menggabungkan data dari sistem yang jamnya ditulis dengan zona berbeda, sedangkan hunt di notebook hampir selalu begitu; satu sumber yang ditulis tanpa offset sudah cukup untuk menggeser semua kesimpulan tujuh jam.

```
pertanyaan hunt butuh join lintas sumber, statistik di luar SPL, atau banyak ambang?
        | tidak                                  | ya
        v                                        v
  tetap di SIEM (Day 06)          persempit di SIEM dengan filter indexed field
                                                 |
                                  tarik SEKALI (REST, token read-only) + ekspor endpoint
                                                 |
                                  manifest: file, SHA-256, jumlah baris = resultCount
                                                 |
       notebook di VM analisis: PARAMETER -> NORMALISASI (UTC, gagal keras) -> analisis
                                                 |        (hitung baris tiap langkah,
                                                 |         merge dengan validate)
                                  label tiap kandidat + uji positif
                                                 |
       ke repo jab-hunt: notebook tanpa output, query, manifest, ringkasan kandidat, laporan
       tetap di VM sampai dihapus: data mentah (retensi tertulis)
       stabil dan diulang tiap minggu tanpa diubah? -> jadi scheduled search di Splunk
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan, kantor pusat dan data center di Jakarta, dan POP regional di Bandung, Surabaya, dan Medan. SOC PT JAB memakai Splunk Enterprise 10.6 dengan Enterprise Security; analyst memakai search head umum `jkt-splunk-sh01` dengan role `jab_hunter`, dan admin Splunk-nya Reza Firmansyah dari tim Infrastruktur. Sejak Februari 2027 kamu (analyst L2) memegang Program hunt PT JAB setiap Selasa dan Kamis, dengan repo GitLab internal `jab-hunt`. Velociraptor `jkt-velo02` menjangkau workstation Windows, termasuk 23 workstation POP Surabaya dan Medan yang tidak punya MDE maupun Sysmon; workstation POP itu keluar ke internet lewat firewall POP masing-masing, bukan lewat proxy, dan saat di luar kantor trafik internetnya tidak lewat PT JAB sama sekali karena VPN memakai split tunnel. Salah satu laptop POP itu, `SBY-WS-0107`, menjadi `INC-2027-040` pada Februari setelah persistence-nya ditemukan lewat hunt scheduled task. Beberapa hunt kuartal pertama butuh hal yang sulit di SPL: menggabungkan hasil Velociraptor dengan log jaringan dan daftar aset, serta analisis interval yang dijalankan ulang setiap kali ambangnya diubah. Rabu 2027-04-07, Reza mengirim catatan bahwa search 28 hari yang sama terlihat berjalan berkali-kali dari akun hunter, dan DPO Agus Setiawan bertanya ke Dimas di mana data hasil ekspor akan disimpan. Rabu sore tim Infrastruktur menyiapkan VM analisis `jkt-hunt-nb01`. Kamis 2027-04-08 pukul 08:10, SOC lead Dimas Prasetyo menulis kepadamu:

> "Pagi. Dua catatan masuk kemarin. Reza minta hunt yang berat jangan lagi dijalankan berulang-ulang di sh01; dia lihat search 28 hari yang sama jalan beberapa kali hanya karena ambangnya diganti. Pak Agus tanya, kalau data diekspor ke VM notebook yang baru, datanya disimpan di mana, siapa yang bisa buka, dan kapan dihapus. VM `jkt-hunt-nb01` sudah disiapkan Infrastruktur kemarin sore. Sebelum dipakai untuk `HUNT-2027-032` hari ini, aku mau aturannya jelas dulu. Kapan sebuah hunt pindah ke notebook dan kapan tetap di Splunk? Bagaimana notebook bisa diulang dan diaudit seperti query `.spl` di repo? Sebenarnya apa yang dikerjakan di notebook yang tidak bisa dikerjakan di SPL? MSTICPy yang sering kamu sebut itu memberi apa, dan apakah ada yang dikirim keluar? Data apa yang boleh diekspor, disimpan di mana, dan berapa lama? Bagaimana kita menghindari salah jam dan baris dobel kalau sumbernya beda-beda? Terakhir, bagaimana hasilnya kembali ke `jab-hunt` supaya tidak jadi file yang hanya ada di VM?"

Pesan itu memuat tujuh pertanyaan:

1. Kapan sebuah hunt dikerjakan di notebook, dan kapan tetap di Splunk?
2. Bagaimana notebook bisa diulang dan diaudit?
3. Apa yang sebenarnya dikerjakan di notebook yang sulit dikerjakan di SPL?
4. Apa yang diberikan MSTICPy, dan apakah ada data yang dikirim keluar?
5. Data apa yang boleh diekspor, disimpan di mana, dan berapa lama?
6. Bagaimana menghindari kesalahan zona waktu dan duplikasi saat menggabungkan sumber?
7. Bagaimana hasil notebook kembali ke repo `jab-hunt`, dan kapan ia berubah menjadi search terjadwal?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2, pertanyaan 3 di bagian 1.3, pertanyaan 4 di bagian 1.4, pertanyaan 5 di bagian 1.5, pertanyaan 6 di bagian 1.6, dan pertanyaan 7 di bagian 1.7. Bagian 2 menjalankan `HUNT-2027-032` di notebook dari abstract sampai laporan, termasuk satu kesalahan zona waktu yang tertangkap sebelum kesimpulan ditulis, dan menutupnya dengan balasan untuk Dimas, Reza, dan Agus.

**Kapan relevan:** saat hunt butuh join lintas sumber yang skemanya berbeda (hasil koleksi endpoint, log jaringan, daftar aset), statistik yang tidak ada di bahasa query SIEM, atau banyak iterasi ambang atas data yang sama; saat data yang dianalisis tidak di-onboard ke SIEM (ekspor Velociraptor, ekspor konfigurasi, CSV dari pemilik sistem); dan saat hasil analisis perlu dilampirkan ke laporan hunt bersama langkah-langkahnya.
**Kapan bukan jawaban:** saat satu search di SIEM sudah menjawab pertanyaannya; saat hunt akan dijadwalkan dan dilihat banyak orang terus-menerus (itu saved search atau dashboard); saat data yang dibutuhkan terlalu besar untuk diekspor dan belum dipersempit di SIEM; dan saat ada insiden aktif, karena bukti insiden dikelola dengan aturan IR, bukan disalin ke VM analisis hunt.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (hunt abstract, stacking, baseline, beacon, CV, Job Inspector, artifact Velociraptor) tidak diulang. Kolom padanan memakai analogi NOC dan SOC yang sama dengan Day lain.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Notebook (Jupyter) | Dokumen berisi sel kode, keluaran, dan teks yang dijalankan oleh kernel; JupyterLab adalah antarmuka web-nya | Skrip analisis gangguan di laptop engineer, dengan catatan dan hasil di file yang sama |
| Kernel | Proses yang menjalankan kode notebook dan menyimpan variabel di memori sampai di-restart | Sesi CLI yang menyimpan state; sesi ditutup, state hilang |
| Sel markdown / sel kode | Sel berisi teks penjelas / sel berisi kode yang dieksekusi | Catatan di tiket di antara output perintah |
| DataFrame (pandas) | Tabel di memori dengan kolom bertipe; satuan kerja pandas | Hasil `stats` yang bisa diolah lagi tanpa search ulang |
| Sel parameter | Satu sel berisi semua nilai yang bisa berubah (rentang, ambang, lokasi file) | Variabel di template konfigurasi perangkat |
| papermill | Alat yang menjalankan notebook dengan nilai parameter dari luar | Menjalankan template konfigurasi dengan variabel per perangkat |
| MSTICPy | Pustaka Python dari Microsoft Threat Intelligence Center untuk investigasi dan hunting di Jupyter | Kotak alat siap pakai, bukan skrip tempelan |
| QueryProvider | Komponen MSTICPy yang menyembunyikan perbedaan antar backend data (Splunk, Sentinel, file lokal) | Satu poller yang bisa diarahkan ke beberapa jenis perangkat |
| TILookup / pivot function | Pengecekan indikator ke provider threat intelligence / fungsi yang menempel pada entitas (IP, domain, host) | Cek reputasi IP ke layanan luar / klik kanan pada perangkat di NMS |
| Token autentikasi Splunk | Token untuk REST atau CLI dengan hak sama dengan akun pemiliknya, dikirim di header `Authorization` | Akun read-only NMS khusus skrip |
| tz-naive / tz-aware | Waktu tanpa / dengan informasi zona waktu | Syslog router tanpa offset vs dengan offset |
| Anti-join | Baris di satu sumber yang tidak punya pasangan di sumber lain | Perangkat di inventaris yang tidak pernah muncul di NMS |
| Validasi merge | Pemeriksaan bahwa kunci join unik di sisi yang semestinya unik | Cek IP ganda di tabel reservasi DHCP sebelum dipakai |
| Manifest ekspor | Daftar file ekspor beserta SHA-256, jumlah baris, query, dan waktu ekspor | Berita acara serah terima barang bukti dengan hash |
| nbstripout | Filter git yang membuang keluaran sel dari versi notebook yang di-commit | Masking data pelanggan sebelum log dibagikan ke vendor |
| Uji positif sintetis | Data buatan dengan pola yang dicari, disisipkan untuk membuktikan analisis sanggup menemukannya | Menyuntikkan alarm uji untuk memastikan jalur notifikasi bekerja |

### 1.1 Kapan notebook, kapan SIEM

Catatan Reza adalah gejala dari pilihan alat yang keliru, bukan dari hunt yang terlalu banyak. Search 28 hari yang dijalankan ulang hanya karena ambang CV atau jumlah koneksi diganti membaca event yang sama berkali-kali dari indexer yang juga dipakai correlation search ES (Day 06 bagian 1.8 menjelaskan kenapa search berat di satu search head bisa membuat search di search head lain terlewat). Data yang sama tidak berubah di antara percobaan; yang berubah hanya cara membacanya.

Tabel berikut memetakan keadaan ke alat. Baca kolom "Alasan", karena alasan itulah yang dipakai saat menjawab Reza.

| Keadaan | Pilih | Alasan |
|---|---|---|
| Mencari satu pola di data bulanan yang besar | SIEM | Index dan akselerasi sudah dibangun untuk itu |
| Hunt yang akan dijadwalkan | SIEM | Notebook terjadwal menambah infrastruktur tanpa menambah nilai |
| Menggabungkan tiga sumber berbeda skema | Notebook | Join lintas skema mahal dan kaku di bahasa query SIEM |
| Statistik yang tidak disediakan SIEM (entropi, klaster, deret waktu) | Notebook | Pustaka Python sudah menyediakannya |
| Iterasi cepat dengan banyak parameter | Notebook | Hasil antara tetap ada di memori, tidak perlu query ulang |
| Data yang tidak di-onboard | Notebook | Tidak perlu membayar ingest untuk analisis sekali jalan |
| Data yang perlu dilihat banyak orang terus-menerus | SIEM | Notebook bukan dashboard |

Aturan praktis: bila kamu menjalankan query yang sama lebih dari tiga kali dengan parameter berbeda, pindahkan ke notebook. Bila kamu menjalankan notebook yang sama tiap minggu tanpa mengubah apa pun, pindahkan ke query terjadwal.

Pindah ke notebook tidak berarti mengekspor semuanya. Polanya "persempit, tarik sekali, iterasi lokal":

- **Persempit di SIEM dengan filter yang murah.** Filter di base search memakai indexed field (`index`, `sourcetype`, `host`) dan rentang absolut, seperti di Day 06 bagian 1.3. Untuk `HUNT-2027-032`, firewall POP punya nama host sendiri (`sby-fw01`, `mdn-fw01`), sehingga search hanya membaca event dari dua firewall itu, bukan seluruh `index=firewall`.
- **Tarik sekali, ukur sekali.** Satu job dengan angka Job Inspector yang dicatat (SID, `runDuration`, `scanCount`, `resultCount`). Itu angka yang dikirim ke Reza sebagai bukti bahwa beban di search head hanya terjadi satu kali.
- **Iterasi lokal.** Semua variasi ambang, join, dan grafik dijalankan di VM analisis. Bila sebuah variasi butuh field yang tidak ikut diekspor, itu tanda query ekspornya perlu diperbaiki dan dijalankan ulang sekali, bukan alasan untuk kembali ke search bar.

Kapan pola ini gagal: data yang dibutuhkan terlalu besar untuk diekspor (misalnya seluruh proxy 28 hari, ratusan juta event). Untuk itu tahap penyempitan tetap di SPL (tahap A di Day 12 bagian 2.1 mengurangi ratusan ribu pasangan menjadi seribuan kandidat), lalu yang diekspor hanya event milik kandidat.

### 1.2 Anatomi notebook hunt yang bisa diulang dan diaudit

Dimas menyamakan notebook dengan query `.spl` di repo: file yang bisa dibaca reviewer dan dijalankan ulang. Notebook bisa memenuhi itu hanya bila strukturnya tetap. Notebook yang berguna enam bulan kemudian punya urutan ini:

1. **Judul dan hipotesis.** Satu sel markdown berisi hipotesis dalam format yang sama dengan Day 03, plus nomor hunt, tanggal, dan nama hunter.
2. **Parameter.** Satu sel kode berisi semua variabel yang bisa berubah: rentang waktu, ambang, jalur file, nama index. Tidak ada angka ajaib tersebar di sel lain.
3. **Versi.** Satu sel yang mencetak versi Python dan paket yang dipakai (pandas, MSTICPy, JupyterLab). Fungsi pustaka berubah antar versi; tanpa catatan versi, notebook yang sama bisa memberi hasil berbeda tahun depan.
4. **Pemuatan data.** Satu sel yang menghasilkan DataFrame, dengan sumbernya tercatat: query persis yang dipakai, file ekspor, SHA-256, dan jumlah barisnya (manifest).
5. **Normalisasi.** Penyeragaman nama kolom, tipe waktu, dan nilai identitas. Ini sel yang paling sering diabaikan dan paling sering menjadi sumber kesimpulan salah (bagian 1.6).
6. **Analisis.** Beberapa sel, masing-masing satu gagasan, dengan sel markdown penjelas di antaranya, dan jumlah baris dicetak setelah setiap filter atau join.
7. **Hasil dan tindakan.** Sel terakhir menuliskan ringkasan kandidat dan labelnya ke file, dan satu sel markdown menyimpulkan apa yang harus terjadi berikutnya.

Yang membedakan notebook hunt dari notebook eksperimen adalah sel markdown di antara sel kode. Tanpa itu, enam bulan lagi kamu hanya punya kode tanpa alasan.

Tiga kebiasaan membuat notebook bisa diaudit, bukan hanya bisa dibaca:

- **Jalankan dari atas setiap kali sebelum menyimpulkan.** Kernel menyimpan variabel di memori. Sel yang dijalankan tidak berurutan, atau sel yang diedit setelah dijalankan, menghasilkan keadaan yang tidak bisa diulang siapa pun. Restart kernel lalu jalankan semua sel sebelum angka apa pun masuk laporan.
- **Parameter dari luar, bukan edit di dalam.** papermill menjalankan notebook dengan nilai parameter dari baris perintah. Sel yang diberi tag `parameters` menjadi tempat nilai bawaan, dan papermill menyisipkan sel baru bertag `injected-parameters` tepat setelahnya, berisi nilai yang ditimpa saat eksekusi [S28]. Akibatnya ada satu jebakan: nilai yang dihitung di dalam sel parameter tidak ikut dihitung ulang. Dokumentasinya memberi contoh `twice = a * 2` di sel parameter; saat dijalankan dengan `a` bernilai 9, `twice` tetap 2 [S28]. Karena itu sel parameter hanya berisi nilai mentah, dan semua turunannya (tanggal UTC, `Path`, batas jendela) dihitung di sel berikutnya.
- **Bukti asal data.** Manifest berisi nama file, SHA-256, jumlah baris, query, dan waktu ekspor. Reviewer bisa mencocokkan jumlah baris dengan `resultCount` job di Splunk dan hash dengan file yang dipakai, tanpa harus mempercayai notebook.

### 1.3 Lima operasi pandas yang menutup sebagian besar hunt

Pertanyaan ketiga Dimas punya jawaban yang lebih sempit dari dugaan banyak orang. Hampir semua hunt di notebook dikerjakan dengan lima operasi pandas; yang membuat notebook berbeda dari SPL adalah bisa menggabungkan kelimanya atas sumber yang skemanya berbeda, dengan hasil antara tetap di memori. Tabel berikut juga menyebut padanan SPL-nya, supaya terlihat bahwa yang baru adalah tempat kerjanya, bukan logikanya [S3].

| Operasi | Gunanya di hunting | Padanan SPL kira-kira |
|---|---|---|
| `value_counts()` | Stacking: frekuensi nilai, lalu lihat ekor paling jarang (Day 05) | `stats count BY x \| sort count` |
| `groupby().agg()` | Agregasi per entitas: hitung, nilai unik, waktu pertama dan terakhir | `stats count dc() min() max() BY ...` |
| `merge()` | Join lintas sumber, termasuk left join untuk mencari yang tidak ada pasangannya | `lookup`, `join`, atau `stats` atas dua sumber |
| `diff()` setelah `sort_values()` | Selisih antar peristiwa berurutan: interval beacon, jeda antar logon | `streamstats current=f last(_time)` |
| `isin()` dan boolean mask | Penyempitan dan pengecualian yang bisa dibaca ulang | `where in(...)` |

Yang kelima terdengar remeh tetapi penting: kondisi penyempitan ditulis sebagai variabel bernama, bukan ditanam di dalam baris panjang, supaya pembaca tahu apa yang kamu buang dan kenapa.

Tiga detail perilaku yang menentukan benar salahnya hasil:

- `groupby(...)["start"].diff()` menghitung selisih di dalam tiap grup saja, dan baris pertama tiap grup bernilai kosong karena tidak punya baris sebelumnya [S19]. Baris kosong itu harus dibuang sebelum statistik dihitung, sama seperti `where isnotnull(delta)` di SPL.
- `merge(how="left")` mempertahankan semua baris kiri dan urutan kuncinya; baris tanpa pasangan mendapat nilai kosong di kolom kanan [S18]. Bila kunci di sisi kanan tidak unik, satu baris kiri berubah menjadi beberapa baris, dan itu terjadi tanpa peringatan (bagian 1.6).
- `std()` di pandas secara bawaan adalah deviasi standar sampel, sama dengan `stdev()` di SPL, sehingga CV dari notebook sebanding dengan CV dari laporan Splunk (Day 05 bagian 1.5).

### 1.4 Apa yang diberikan MSTICPy

Pertanyaan keempat Dimas punya dua bagian: apa gunanya, dan apakah ada yang dikirim keluar. Jawaban bagian kedua bergantung pada komponen mana yang dipakai.

MSTICPy adalah pustaka Python dari Microsoft Threat Intelligence Center untuk investigasi dan hunting di dalam Jupyter [S1]. Gunanya mengganti kode tempel yang biasanya kamu tulis sendiri dengan komponen yang sudah teruji, sehingga notebook tetap terbaca. Empat kelompok komponennya [S1]:

- **Pengambilan data.** `QueryProvider` dengan backend untuk MSSentinel, MSDefender, MSGraph, Splunk, Kusto, Sumologic, OSQuery, Velociraptor, Cybereason, dan `LocalData` untuk file lokal. Rilis 3.0.0 menambah provider OpenObserve [S2].
- **Pengayaan.** `TILookup` dan sekumpulan TI provider, lookup GeoIP (Maxmind, IPStack), dan IP Whois.
- **Analisis.** `Base64Unpack`, `IoCExtract`, `EventClustering`, `AnomalousSequence`, dan `PivotFunctions`.
- **Visualisasi.** `EventTimeline`, `ProcessTree`, `FoliumMap`, `TimeSeriesAnomalies`, `MatrixPlot`, `EntityGraph`, dan `NetworkGraph`.

Tiga yang paling cepat memberi nilai untuk pekerjaan sehari-hari: `IoCExtract` untuk menarik indikator dari teks bebas, `TILookup` untuk memeriksa indikator secara massal, dan `ProcessTree` untuk membaca rantai proses tanpa menyusun ulang sendiri.

Perilaku komponen yang dipakai di PT JAB, dari dokumentasi dan kode sumbernya:

- **Splunk.** Provider dibuat dengan `QueryProvider("Splunk")` dan butuh paket tambahan `msticpy[splunk]` (Splunk SDK for Python) [S6]. `connect()` menerima `host` (port bawaan 8089) dan salah satu dari pasangan `username`/`password` atau `bearer_token`; bila keduanya diisi, autentikasi user dan password yang dipakai [S6]. Karena itu konfigurasi di nb01 hanya berisi host dan token, tanpa username. Di kode driver, query dijalankan sebagai job biasa (bukan endpoint export) lalu hasilnya diambil per halaman; argumen `timeout` bawaannya 60 detik, `page_size` 100 baris, dan `count` 0 (tanpa batas) [S7]. `exec_query()` meneruskan argumen tambahan itu ke driver [S8]. Hasilnya DataFrame, dan driver tidak mengubah `_time` menjadi tipe waktu [S7], sehingga normalisasi waktu tetap tugasmu.
- **Velociraptor.** Provider `VelociraptorLogs` membaca file JSON hasil koleksi (satu record per baris) dari folder `data_paths`; satu tabel per jenis artifact, hasil dari banyak host digabung, dan fungsi query-nya tidak memfilter apa pun, jadi penyaringan dilakukan dengan pandas [S13].
- **IoCExtract.** Mengekstrak `ipv4`, `ipv6`, `dns`, `url`, path Windows dan Linux, serta hash MD5, SHA-1, dan SHA-256 dari kolom teks DataFrame; keluarannya kolom `IoCType`, `Observable`, dan `SourceIndex` yang menunjuk ke baris asal [S11]. Ekstraksi berjalan lokal, tanpa koneksi ke luar.
- **TILookup.** Tanpa argumen, `TILookup()` memuat semua provider yang punya entri di `msticpyconfig.yaml`; `providers=[...]` membatasinya [S9]. `lookup_iocs()` menerima DataFrame dengan `ioc_col` untuk kolom indikator dan `ioc_type_col` untuk kolom tipenya [S10]. Provider yang disebut dokumentasi antara lain VirusTotal, AlienVault OTX, RiskIQ, IBM XForce, MS Sentinel TI, GreyNoise, CrowdSec, AbuseIPDB, dan ScanMalware [S9]; semuanya layanan di luar jaringanmu, kecuali MS Sentinel TI yang membaca workspace milik organisasi sendiri.
- **Pivot.** `init_notebook()` sudah menyiapkan pivot, sehingga entitas seperti `IpAddress` dan `Dns` langsung punya fungsi seperti `util.whois` dan `util.geoloc`; DataFrame bisa dikirim lewat `data` dan `column`, dan `join="left"` mempertahankan semua baris input [S12]. Whois dan pivot TI bekerja dengan menghubungi layanan atau provider yang dikonfigurasi, jadi di mesin tanpa internet fungsi itu tidak berguna; cek kebutuhan jaringan tiap fungsi di dokumentasi versi-mu.

Jadi jawaban "apakah ada yang dikirim keluar": pengambilan data dari Splunk dan Velociraptor, IoCExtract, dan analisis pandas tidak mengirim apa pun ke luar PT JAB. TILookup dan sebagian pivot mengirim indikator ke layanan pihak ketiga. Itu tindakan yang perlu persetujuan: indikator dari jaringan internal, nama host, atau akun bisa membocorkan informasi tentang organisasimu dan memberi tahu penyerang bahwa ia sedang diselidiki bila provider membagikan query ke pihak lain. Kirim hanya indikator eksternal yang memang perlu diperiksa. Di PT JAB keputusan itu dibuat sekali di desain VM: `jkt-hunt-nb01` tidak punya akses internet selain ke repositori paket, `msticpyconfig.yaml` di sana tidak memuat TI provider, dan pengecekan indikator eksternal dilakukan lewat threat intelligence ES yang sudah dipakai L1 untuk pencarian IOC (Day 03).

Konfigurasi terpusat di `msticpyconfig.yaml`, dan di situ pula kunci API tersimpan [S1]. File itu tidak boleh masuk repo; perlakukan sama seperti kredensial lain. Dokumentasi TI provider menganjurkan kunci diambil dari variabel lingkungan atau key vault, bukan ditulis sebagai teks biasa [S9].

Versi menentukan apa yang bisa dipasang. MSTICPy 3.1.0 (21 September 2026) adalah rilis terbaru; seri 3.x membuang dukungan Python 3.8 dan 3.9 dan kini mendukung Python 3.10 sampai 3.14 [S2]. File requirements di repo MSTICPy masih membatasi pandas di bawah 3.0 [S14], padahal pandas terbaru adalah 3.0.6 (17 September 2026) dan rilis terakhir seri 2.x adalah 2.3.3 (29 September 2025) [S17]. Konsekuensinya untuk nb01: lingkungan Python yang memuat MSTICPy dikunci ke pandas 2.3.3. Cek metadata paket 3.1.0 saat memasang, karena file requirements di cabang utama bisa berbeda dengan rilisnya. Karena pustaka ini bergerak, versi yang terpasang dicatat di sel versi dan di laporan hunt.

### 1.5 Lingkungan notebook dan data ekspor

Pertanyaan Agus adalah pertanyaan yang benar: begitu data keluar dari Splunk, retensi dan hak akses Splunk tidak lagi melindunginya. Jawabannya ada di desain VM dan di aturan ekspor, bukan di niat baik analyst.

Lingkungan yang disiapkan tim Infrastruktur Rabu 2027-04-07:

- **VM `jkt-hunt-nb01` (`10.20.1.52`) di jaringan manajemen**, tidak join domain, dengan akun lokal per hunter (kamu dan Rudi Hartanto sebagai cadangan). SSH hanya dari subnet SOC. JupyterLab hanya mendengarkan di `127.0.0.1` dan dibuka lewat SSH tunnel, sehingga tidak ada antarmuka web notebook yang terbuka di jaringan.
- **Disk terenkripsi.** Data hunt di `/data/hunt/<HUNT-ID>/`, dengan subfolder `raw/` (ekspor mentah) dan `out/` (ringkasan yang boleh keluar VM), izin hanya untuk pemilik dan grup hunter.
- **Tanpa akses internet** kecuali lewat proxy dengan daftar izin ke repositori paket Python untuk memasang dan memperbarui paket. Tidak ada TI provider, whois, atau GeoIP online dari VM ini (bagian 1.4).
- **Akses ke sumber data dibatasi firewall:** `jkt-splunk-sh01` port 8089 untuk REST API, dan API Velociraptor di `jkt-velo02` untuk membaca hasil hunt.
- **Splunk lewat token.** Reza menerbitkan token untuk akun hunter-mu (role `jab_hunter`, hanya search, tanpa hak menulis ke index atau knowledge object di luar app hunt), berlaku 90 hari. Token hanya untuk REST dan CLI, tidak bisa dipakai login ke Splunk Web, hanya berlaku di instance yang menerbitkannya, dan hak aksesnya sama dengan akun pemiliknya [S23]. Token disimpan di file lingkungan dengan izin hanya-pemilik dan dibaca lewat variabel lingkungan `JAB_SPLUNK_TOKEN`, tidak pernah ditulis di sel.
- **Velociraptor lewat API.** API Velociraptor adalah layanan gRPC dengan satu method `Query` untuk menjalankan VQL; client config dibuat di server dengan `config api_client`, pengguna API butuh minimal role `api`, sertifikat client berlaku satu tahun, dan dokumentasinya menganjurkan role sekecil mungkin, bukan `administrator` [S29]. Dimas membuat akun API khusus nb01 dengan role baca hasil ditambah `api`; cek bahwa role baca di versi-mu memberi izin `READ_RESULTS`, yang dibutuhkan plugin `hunt_results()` [S30].

Data yang boleh diekspor mengikuti prinsip minimal:

- Hanya field yang dibutuhkan hipotesis. Ekspor firewall `HUNT-2027-032` memuat waktu, firewall, ID sesi, IP sumber dan tujuan, port, aplikasi, durasi, dan byte. Tidak ada `_raw`, tidak ada URL lengkap, tidak ada isi email atau dokumen.
- Hanya rentang dan host yang ada di abstract. Ekspor "sekalian semua, siapa tahu perlu" adalah cara salinan data pribadi bertambah tanpa alasan.
- Nama akun dan nama host ikut bila memang menjadi kunci analisis atau konfirmasi; ringkasan yang keluar VM tidak memuat lebih banyak identitas daripada laporan hunt itu sendiri.

Retensi yang ditetapkan untuk data ekspor mentah: dihapus 14 hari setelah laporan hunt disetujui Dimas, dan paling lambat 30 hari setelah tanggal ekspor, mana yang lebih dulu. Alasannya:

- **Sumbernya tetap ada di Splunk.** Bila analisis perlu diulang dalam retensi sumber, ekspor bisa ditarik lagi dengan query di manifest. Salinan tidak perlu disimpan "untuk jaga-jaga".
- **Salinan tidak boleh hidup lebih lama dari sumbernya.** Proxy dan DNS di Splunk hanya disimpan 30 hari. Salinan di VM yang bertahan tiga bulan berarti memperpanjang umur data pribadi karyawan tanpa keputusan siapa pun; batas 30 hari dari tanggal ekspor mencegahnya untuk sumber yang retensinya paling pendek.
- **14 hari cukup untuk review dan pertanyaan susulan.** Dimas biasanya menyetujui laporan dalam satu sampai dua hari, dan pertanyaan pemilik sistem tentang label jinak datang dalam minggu yang sama.
- **Pengecualian tertulis:** bila hunt menemukan sesuatu dan diserahkan ke IR, file ekspor yang relevan diserahkan sebagai bukti beserta hash-nya dan dikelola dengan aturan bukti IR. Salinan di nb01 tetap dihapus menurut aturan hunt.

Yang tidak pernah dihapus menurut aturan ini adalah isi folder `out/` yang sudah masuk `jab-hunt` (bagian 1.7): notebook tanpa output, query, manifest, ringkasan kandidat, dan laporan. Isinya setara dengan laporan hunt, bukan data mentah.

Tiga aturan higiene yang dijalankan sejak notebook pertama:

- Bersihkan output sebelum menyimpan notebook yang akan dibagikan, dan jangan pernah commit notebook berisi data kerja ke repo, baik repo `jab-hunt` maupun repo catatan pribadi.
- Simpan data mentah di luar repo, dan rujuk lewat jalur di sel parameter. Yang masuk repo cukup notebook dan hasil ringkasannya.
- Kunci dan token tinggal di `msticpyconfig.yaml` atau variabel lingkungan, tidak pernah di dalam sel.

### 1.6 Waktu dan duplikasi: dua kesalahan yang tidak memunculkan error

Pertanyaan keenam Dimas menyentuh dua kesalahan yang paling mahal di notebook justru karena keduanya tidak memunculkan error. Kode berjalan, tabel keluar, grafik terlihat masuk akal, dan kesimpulannya salah.

**Zona waktu.** PT JAB pernah mengalami versi SIEM dari masalah ini: Day 04 bagian 2.5 menemukan empat belas perangkat POP Medan yang menulis jam WIB tanpa offset, sehingga `_time`-nya bergeser tujuh jam. Di notebook, sumber kesalahan yang sama muncul dari tiga arah sekaligus:

- Velociraptor menulis waktu dalam UTC, dalam format ISO 8601 berakhiran `Z`.
- Splunk menyimpan `_time` sebagai epoch, tetapi `strftime()` di SPL menghasilkan teks menurut zona waktu tampilan akun yang menjalankan search, tanpa offset kecuali format-nya memuat `%z`.
- File dari pemilik sistem (daftar reservasi DHCP, tiket, jadwal) biasanya ditulis dalam jam lokal tanpa zona.

`pd.to_datetime(..., utc=True)` sering dianggap pengaman, padahal perilakunya ada dua: input yang sudah punya zona dikonversi ke UTC, sedangkan input tanpa zona dianggap sudah UTC (dilokalisasi sebagai UTC) [S15]. Teks "2027-03-15 09:14:03" yang sebenarnya WIB diam-diam menjadi 09:14 UTC, yaitu 16:14 WIB. Tidak ada peringatan. Aturannya:

- Ekspor waktu sebagai epoch dari Splunk (`eval epoch=_time`) dan urai dengan `unit="s", utc=True`. Epoch tidak punya zona, jadi tidak bisa salah tafsir.
- Normalisasi menolak teks waktu tanpa zona (gagal keras dengan pesan yang menyebut kolomnya), alih-alih menebak.
- Bila zona sebuah file diketahui pasti (misalnya tanggal koleksi yang kamu tulis sendiri dalam WIB), lokalisasi eksplisit dengan zona itu, lalu konversi ke UTC.
- Semua perhitungan dalam UTC; konversi ke `Asia/Jakarta` hanya untuk tampilan dan untuk pengelompokan per tanggal atau per jam kerja. Tanggal yang diambil dari waktu UTC salah untuk WIB: logon pukul 06:30 WIB adalah 23:30 UTC hari sebelumnya.
- Bila pembanding waktu dari dua sumber berselisih hampir persis tujuh jam, anggap itu zona waktu sampai terbukti sebaliknya.

pandas 3.0 menambah satu hal yang perlu diketahui bila suatu saat lingkunganmu memakainya: resolusi datetime kini disimpulkan dari input (teks menjadi mikrodetik, epoch detik tetap detik), dan konversi ke integer bisa memberi angka seribu kali lebih kecil dari dugaan; catatan rilisnya menganjurkan `as_unit()` alih-alih `astype("int64")` [S16]. Notebook di Day ini tidak pernah mengubah waktu menjadi integer; selisih dihitung dengan `diff()` lalu `dt.total_seconds()`.

**Duplikasi.** Baris dobel di notebook datang dari tiga tempat, dan masing-masing punya pemeriksaannya:

- **Koleksi yang tumpang tindih.** Hunt Velociraptor mingguan mengumpulkan task yang sama dari host yang sama setiap minggu. Empat koleksi dari satu laptop berarti empat baris untuk satu task. Stacking harus menghitung host unik (`nunique`), bukan baris, dan tabel per host dirapatkan dulu dengan `drop_duplicates(subset=[...])`, yang memakai kolom tertentu saja sebagai penentu duplikat [S20]. Ini kesalahan yang sama dengan `count()` versus jumlah host di VQL (Day 09 bagian 2.3).
- **Join yang membengkak.** `merge()` dengan kunci yang tidak unik di sisi kanan menggandakan baris kiri. `validate="many_to_one"` memeriksa bahwa kunci unik di sisi kanan, dan `validate="one_to_one"` memeriksa keduanya; `indicator=True` menambah kolom `_merge` bernilai `left_only`, `right_only`, atau `both` [S18]. Bila validasi gagal, pandas berhenti dengan error, dan itu yang diinginkan.
- **Ekspor yang dobel.** File yang diunduh dua kali dan digabung, atau halaman hasil yang terambil ulang. Bandingkan jumlah baris file dengan `resultCount` job, dan periksa duplikat pada kunci alami sumbernya (untuk firewall: firewall dan ID sesi).

Kebiasaan yang menutup keduanya: cetak jumlah baris sebelum dan sesudah setiap filter, dedup, dan join. Angka yang tidak bisa kamu jelaskan adalah tanda masalah normalisasi, lebih cepat daripada pemeriksaan lain.

### 1.7 Hasil notebook kembali ke repo dan ke Splunk

Pertanyaan terakhir Dimas mencegah masalah yang biasa terjadi: analisis yang bagus hidup di satu VM, lalu hilang bersama data mentahnya saat retensi berjalan. Yang kembali ke `jab-hunt/hunts/HUNT-2027-NNN/` ada lima:

- **Notebook tanpa output** (`notebook/HUNT-2027-NNN.ipynb`). Output sel memuat nama pengguna, IP internal, dan isi perintah, dan semua itu ikut tersimpan ke file `.ipynb` bila tidak dibersihkan.
- **Query** (`queries/*.spl`, `queries/*.vql`) persis seperti yang dijalankan, sama dengan aturan di Day 06 bagian 1.5.
- **Manifest** (`notebook/manifest.json`): file ekspor, SHA-256, jumlah baris, query, SID, dan waktu ekspor. Data mentahnya tidak ikut; manifest membuktikan apa yang dianalisis.
- **Ringkasan kandidat** (`notebook/kandidat.csv`): beberapa puluh baris kandidat beserta label dan alasan, bukan jutaan sesi.
- **Laporan** (`report.md`) dengan format Day 07 bagian 1.9, ditambah baris lingkungan (VM, versi paket).

Dua cara membersihkan output, dengan sifat berbeda:

- `jupyter nbconvert --clear-output <notebook>` menghapus output dan menyimpan file di tempat, menimpa notebook aslinya [S27]. Ini mengubah working copy; setelahnya notebook harus dijalankan ulang untuk melihat hasil.
- `nbstripout --install` di repo memasang filter git yang membuang output, execution count, dan sebagian metadata dari versi yang di-commit, sedangkan working copy tetap utuh [S26]. Filter ini dideklarasikan wajib, sehingga konfigurasi yang rusak menghasilkan error alih-alih lolos diam-diam [S26]. Konsekuensinya: repo bersih, tetapi file notebook di nb01 tetap berisi output data, dan itu tunduk pada retensi yang sama dengan `raw/`.

Pemeriksaan terakhir sebelum push tetap manual: buka file `.ipynb` di editor teks dan cari nama host, IP, atau akun dari data. Filter yang terpasang di satu clone tidak terpasang di clone lain.

Hubungan dengan Splunk mengikuti aturan praktis bagian 1.1. Bagian analisis yang stabil, diulang tiap minggu tanpa diubah, dan bisa ditulis di SPL, dipindah menjadi scheduled search di luar jam puncak dengan `schedule_window` (Day 06 bagian 1.4), dan diserahkan ke Sari Kusuma sebagai laporan, bukan alert, kecuali sudah melewati jalur hunt ke deteksi. Bagian yang hanya bisa dikerjakan di notebook (join dengan hasil Velociraptor, misalnya) tetap di notebook dan dijalankan per hunt dengan papermill, dengan parameter rentang yang baru. Notebook bukan dashboard dan bukan pengganti scheduled search.

## 2. Contoh dan langkah praktis: `HUNT-2027-032` di notebook

Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi. Kode ditulis untuk Python 3.12, pandas 2.3.3, dan MSTICPy 3.1.0 di `jkt-hunt-nb01`; untuk latihan, jalankan versi yang disesuaikan di lab pribadi (bagian 3). Hunt ini menjawab permintaan Dimas dengan contoh nyata: satu tarikan data ke search head, semua iterasi di VM, dan data yang dikelola dari ekspor sampai dihapus.

### 2.1 Abstract `HUNT-2027-032`

Pemicunya pelajaran `INC-2027-040`: laptop POP yang jarang di kantor memasang persistence di profil pengguna, dan tidak ada MDE maupun Sysmon untuk melihat prosesnya. Hasil Velociraptor memberi keadaan host (task dan autostart yang terpasang), firewall POP memberi perilaku jaringan saat laptop berada di kantor, dan daftar aset memberi konteks. Tidak satu pun sumber itu cukup sendirian, dan menggabungkannya di SPL berarti mengindeks hasil Velociraptor terlebih dulu. Itu alasan hunt ini dikerjakan di notebook.

```
ID             : HUNT-2027-032
Dibuat         : Kamis 2027-04-08 08:40, pemilik: <kamu>, reviewer: Dimas Prasetyo
Trigger        : Backlog dari INC-2027-040 / HUNT-2027-013: laptop jarang di kantor memasang
                 persistence di profil; 23 workstation POP Surabaya dan Medan tanpa MDE dan Sysmon
Tipe (PEAK)    : Hypothesis-driven; stacking + analisis frekuensi + join lintas sumber, di notebook
Hipotesis      : Di workstation POP ada program di lokasi yang bisa ditulis pengguna yang terdaftar
                 sebagai scheduled task atau autostart, langka di seluruh fleet, dan saat laptop di
                 kantor POP menghubungi tujuan eksternal berprevalence rendah dengan interval teratur,
                 tanpa pemilik atau alasan sah.
ATT&CK         : T1053.005 Scheduled Task; T1547.001 Registry Run Keys / Startup Folder;
                 T1071.001 Web Protocols
Data           : (1) jkt-velo02: hunt mingguan Windows.System.TaskScheduler/Analysis dan
                 Windows.Sys.StartupItems, Kamis 2027-03-11, 03-18, 03-25, 04-01 (semua client Windows)
                 (2) index=firewall pan:traffic pan_traffic_end dari sby-fw01 dan mdn-fw01,
                 Kamis 2027-03-11 00:00 sampai Kamis 2027-04-08 00:00 WIB (28 hari)
                 (3) jab_assets.csv (ekspor AD 2027-04-07)
                 (4) daftar reservasi DHCP workstation POP dari NOC (2027-04-07)
Lingkungan     : jkt-hunt-nb01, /data/hunt/HUNT-2027-032/; satu tarikan Splunk, dicatat SID-nya
Di luar cakupan: laptop saat di luar kantor (split tunnel); MDN-WS-0019 (servis di vendor);
                 tujuan dengan dest_hosts > 10; interval > 4 jam; autostart lewat service atau WMI
Kriteria sukses: Semua kandidat autostart (hosts <= 3 di fleet, lokasi user-writable) dan semua
                 pasangan beacon yang lolos diberi label; setiap pasangan beacon dikaitkan atau
                 dinyatakan tidak terkait dengan entri autostart di host yang sama
FP yang diduga : Updater per-user, agent perangkat (modem USB), aplikasi pihak ketiga tim Keuangan
Handover       : IR (Dimas) bila ditemukan; Sari Kusuma untuk laporan terjadwal; NOC untuk data DHCP
Target selesai : Kamis 2027-04-08
```

Cara membaca elemen yang baru dibanding abstract sebelumnya:

- **Lingkungan** menyebut VM dan folder, supaya reviewer tahu di mana data hidup dan aturan retensi mana yang berlaku.
- **Data (4)** adalah file dari pemilik sistem, bukan dari SIEM. Abstract menyebut tanggal ekspornya, karena reservasi DHCP berubah.
- **Kriteria sukses** memuat sisi join: pasangan beacon tanpa entri autostart yang bisa menjelaskannya justru kandidat paling menarik, dan harus terlihat di hasil.

**Kapan gagal:** abstract tidak menyebut lingkungan dan data dari pemilik sistem, sehingga laporan tidak bisa menjelaskan kenapa angka join berbeda saat diulang bulan depan dengan daftar reservasi yang sudah berubah.

### 2.2 Sel parameter, versi, dan normalisasi

Tiga sel pertama notebook ini adalah jawaban konkret untuk pertanyaan kedua Dimas: semua yang bisa berubah ada di satu tempat, versinya tercatat, dan normalisasi menolak data yang tidak bisa ditafsirkan.

**Tujuan:** menetapkan parameter hunt, menghitung turunannya, mencatat versi, dan menyediakan fungsi normalisasi yang dipakai semua sumber.

Sel parameter (diberi tag `parameters` untuk papermill), selalu di atas:

```python
PARAMS = {
    "hunt_id": "HUNT-2027-032",
    "mulai": "2027-03-11T00:00:00+07:00",
    "selesai": "2027-04-08T00:00:00+07:00",
    "zona": "Asia/Jakarta",
    "data_dir": "/data/hunt/HUNT-2027-032/raw",
    "out_dir": "/data/hunt/HUNT-2027-032/out",
    "splunk_host": "jkt-splunk-sh01.corp.jab.example",
    "kota_pop": ["surabaya", "medan"],
    "ambang_langka": 3,
    "ambang_konteks": 10,
    "max_dest_hosts": 10,
    "min_conns": 20,
    "min_hours": 12,
    "med_min": 30,
    "med_max": 14400,
    "cv_max": 0.2,
    "gap_factor": 3,
    "jendela_baru_hari": 7,
    "baseline_hari": 21,
}
```

Sel turunan dan versi:

```python
import platform
from importlib.metadata import version
from pathlib import Path

import pandas as pd

DATA_DIR = Path(PARAMS["data_dir"])
OUT_DIR = Path(PARAMS["out_dir"])
MULAI = pd.Timestamp(PARAMS["mulai"]).tz_convert("UTC")
SELESAI = pd.Timestamp(PARAMS["selesai"]).tz_convert("UTC")

VERSI = {paket: version(paket) for paket in ("pandas", "numpy", "msticpy", "jupyterlab")}
VERSI["python"] = platform.python_version()
print(PARAMS["hunt_id"], MULAI, SELESAI)
print(VERSI)

pd.set_option("display.max_columns", 50)
pd.set_option("display.width", 200)
```

Sel normalisasi, yang menentukan benar salahnya semua analisis sesudahnya:

```python
ZONA_DI_UJUNG = r"(?:Z|[+-]\d{2}:?\d{2})$"


def normalisasi(df, kolom_waktu="timestamp", unit=None):
    df = df.copy()
    if unit:
        angka = pd.to_numeric(df[kolom_waktu], errors="coerce")
        df[kolom_waktu] = pd.to_datetime(angka, unit=unit, utc=True)
    else:
        teks = df[kolom_waktu].astype("string")
        tanpa_zona = ~teks.str.contains(ZONA_DI_UJUNG, regex=True, na=True)
        if tanpa_zona.any():
            raise ValueError(
                f"{int(tanpa_zona.sum())} nilai {kolom_waktu} tanpa zona waktu, "
                f"contoh: {teks[tanpa_zona].iloc[0]}"
            )
        df[kolom_waktu] = pd.to_datetime(teks, utc=True, errors="coerce", format="ISO8601")
    for kolom in ("user", "host", "process"):
        if kolom in df.columns:
            df[kolom] = df[kolom].astype("string").str.strip().str.lower()
    hilang = df[kolom_waktu].isna().sum()
    if hilang:
        print(f"peringatan: {hilang} baris tanpa timestamp yang bisa diurai")
    return df.dropna(subset=[kolom_waktu]).sort_values(kolom_waktu)


def host_pendek(nilai):
    return nilai.astype("string").str.strip().str.lower().str.split(".").str[0]
```

Tabel berikut menjelaskan bagian yang menentukan; baca kolom kanan untuk alasan tiap pilihan.

| Bagian | Fungsi |
|---|---|
| Nilai mentah di `PARAMS`, turunan di sel berikutnya | papermill hanya menimpa sel parameter; turunan yang dihitung di sel itu tidak ikut berubah [S28] |
| `mulai`/`selesai` dengan offset `+07:00` | Rentang ditulis dalam WIB seperti abstract, lalu dikonversi ke UTC untuk perhitungan |
| `VERSI` dari `importlib.metadata` | Versi yang benar-benar terpasang, bukan yang diniatkan |
| `unit="s", utc=True` untuk epoch | Epoch tidak punya zona, jadi tidak bisa salah tafsir |
| `raise ValueError` untuk teks tanpa zona | `utc=True` akan menganggap teks tanpa zona sebagai UTC [S15]; lebih baik berhenti daripada menebak |
| `errors="coerce"` lalu cetak jumlah `NaT` | Baris rusak menjadi `NaT` dan jumlahnya terlihat; baris yang dibuang diam-diam adalah cara klasik menghasilkan kesimpulan salah [S15] |
| `.str.strip().str.lower()` | `SBY-WS-0115`, `sby-ws-0115`, dan `SBY-WS-0115 ` adalah satu host tetapi tiga nilai bagi pandas |
| `host_pendek()` | Velociraptor bisa memberi FQDN (`sby-ws-0115.corp.jab.example`), `jab_assets.csv` memberi nama pendek; disamakan di satu fungsi |

Keluaran ilustrasi sel versi:

```
HUNT-2027-032 2027-03-10 17:00:00+00:00 2027-04-07 17:00:00+00:00
{'pandas': '2.3.3', 'numpy': '2.4.6', 'msticpy': '3.1.0', 'jupyterlab': '4.6.4', 'python': '3.12.11'}
```

**Cara membaca hasil:** rentang 11 Maret sampai 8 April WIB tercetak sebagai 10 Maret 17:00 sampai 7 April 17:00 UTC. Itu benar, dan baris ini adalah pemeriksaan zona waktu pertama yang dilihat reviewer.

**Variasi:** untuk sumber yang zonanya diketahui pasti tetapi tidak tertulis (misalnya tanggal koleksi yang kamu tulis sendiri dalam WIB), pakai `pd.to_datetime(nilai).dt.tz_localize(PARAMS["zona"]).dt.tz_convert("UTC")`, yang menyatakan zonanya secara eksplisit.

**Kapan gagal:** parameter disalin ke sel lain "supaya praktis", sehingga dua nilai ambang hidup bersamaan; atau versi paket dicatat dari ingatan, bukan dari lingkungan yang menjalankan.

### 2.3 Mengambil data sekali: Splunk, Velociraptor, dan file pemilik sistem

Bagian ini adalah inti jawaban untuk Reza: satu job di `jkt-splunk-sh01` (diulang satu kali setelah perbaikan zona waktu di bagian 2.6), satu tarikan dari Velociraptor, dan manifest yang membuktikan isinya.

**Tujuan:** menarik sesi firewall POP 28 hari dan hasil hunt mingguan Velociraptor ke `raw/`, lalu mencatat hash dan jumlah barisnya.

Query Splunk disimpan di `queries/fw-pop.spl`:

```
search index=firewall sourcetype=pan:traffic eventtype=pan_traffic_end
    (host=sby-fw01 OR host=mdn-fw01)
    earliest="03/11/2027:00:00:00" latest="04/08/2027:00:00:00"
    (src=10.40.0.0/16 OR src=10.50.0.0/16)
    NOT dest=10.0.0.0/8 NOT dest=172.16.0.0/12 NOT dest=192.168.0.0/16
| eval epoch=_time
| rename host AS fw
| table epoch fw session_id src dest dest_port app duration bytes_out bytes_in
```

| Bagian | Fungsi |
|---|---|
| `search` di awal | Lewat REST, string search harus diawali command `search` |
| `host=sby-fw01 OR host=mdn-fw01` | Indexed field: hanya event dari dua firewall POP yang dibaca, bukan seluruh `index=firewall` |
| `eventtype=pan_traffic_end` | Satu baris per sesi (log akhir sesi), supaya sesi tidak terhitung dua kali (Day 12 bagian 2.1) |
| `earliest="03/11/2027:00:00:00" ...` | Rentang absolut; dibaca dalam zona waktu akun yang menjalankan search, jadi pastikan preferensi zona akun hunter-mu WIB |
| `src=10.40.0.0/16 OR src=10.50.0.0/16` | Subnet POP Surabaya dan Medan |
| `NOT dest=...` | Hanya tujuan eksternal |
| `eval epoch=_time` | Waktu dikirim sebagai epoch, bukan teks berformat (bagian 1.6) |
| `table ...` | Hanya field yang dibutuhkan hipotesis; tanpa `_raw` (bagian 1.5). Nama field `session_id` mengikuti add-on Palo Alto; cek di datamu |

Sel pengambilan lewat MSTICPy:

```python
import os

import msticpy as mp

mp.init_notebook()

qry = mp.QueryProvider("Splunk")
qry.connect(host=PARAMS["splunk_host"], bearer_token=os.environ["JAB_SPLUNK_TOKEN"])

spl_fw = Path("queries/fw-pop.spl").read_text()
fw_raw = qry.exec_query(spl_fw, timeout=900, page_size=10000)
print("baris dari Splunk:", len(fw_raw))
fw_raw.to_csv(DATA_DIR / "fw-pop-20270311-20270408.csv.gz", index=False)
```

- `bearer_token` dari variabel lingkungan; tanpa `username`, karena bila keduanya ada, autentikasi user yang dipakai [S6].
- `timeout=900`: bawaan driver 60 detik dan job 28 hari bisa lebih lama dari itu; `page_size=10000` mengurangi jumlah permintaan dibanding bawaan 100 baris [S7]. Argumen itu diteruskan `exec_query()` ke driver [S8]. Nilai `page_size` yang lebih besar bisa dibatasi pengaturan hasil maksimum di sisi Splunk; cek bersama Reza bila hasil terpotong.
- Job ini adalah job biasa milik akunmu (driver tidak memakai endpoint export) [S7], jadi ia muncul di Activity > Jobs dengan SID dan bisa dibuka di Job Inspector seperti search dari search bar. Kuota dan workload rule untuk role `jab_hunter` berlaku sama.
- `.csv.gz`: pandas memilih kompresi dari ekstensi file.

Untuk pengambilan sekali tanpa MSTICPy, endpoint export mengalirkan hasil saat tersedia tanpa membuat SID yang bisa diakses kemudian [S22]. Untuk Splunk di atas 9.0.1, endpoint berversi `search/v2/jobs/export` dianjurkan karena endpoint tanpa versi sudah deprecated [S24]; cek jalurnya di REST API Reference versi-mu. Output yang tersedia antara lain `csv`, `json`, dan `xml` [S21], dan token dikirim di header `Authorization: Bearer` ke port manajemen [S23]:

```bash
curl -sS --cacert /etc/pki/jab/jab-root-ca.pem \
  -H "Authorization: Bearer ${JAB_SPLUNK_TOKEN}" \
  https://jkt-splunk-sh01.corp.jab.example:8089/services/search/v2/jobs/export \
  --data-urlencode search@queries/fw-pop.spl \
  -d output_mode=csv \
  | gzip > /data/hunt/HUNT-2027-032/raw/fw-pop-20270311-20270408.csv.gz
```

Karena export tidak meninggalkan SID untuk dibuka kemudian, angka Job Inspector-nya tidak bisa dilampirkan ke laporan. Itu alasan PT JAB memakai job biasa untuk tarikan yang angkanya harus dikirim ke Reza.

Hasil Velociraptor diambil lewat API dengan VQL yang menyeragamkan kolom dan menambahkan nama host. `client_info(client_id=...)` mengembalikan informasi client dari datastore, termasuk `os_info.hostname` [S31], dan `hunt_results()` membaca hasil satu hunt untuk satu artifact dan source [S30]. Nilai hunt ID dikirim sebagai variabel, bukan disisipkan ke string VQL, mengikuti anjuran dokumentasi API [S29]:

```
SELECT ClientId,
       client_info(client_id=ClientId).os_info.hostname AS Hostname,
       Koleksi, "task" AS Mekanisme,
       TaskName AS Entry, Command AS Path, Arguments, RegistrationTime
FROM hunt_results(hunt_id=HuntId, artifact="Windows.System.TaskScheduler", source="Analysis")
```

Query kedua untuk `Windows.Sys.StartupItems` memakai `Name AS Entry` dan `Details AS Path`, dengan `"startup" AS Mekanisme` dan `RegistrationTime` kosong, karena artifact itu tidak punya timestamp (Day 10). Keduanya dijalankan dari terminal nb01 untuk setiap hunt mingguan:

```bash
pyvelociraptor --config ~/.velo/api_nb01.yaml \
  --env HuntId=H.D1A7K0Q2M3T4P --env Koleksi=2027-03-11 \
  "$(cat queries/velo-task.vql)" > raw/velo-task-2027-03-11.out
```

Keluaran CLI lalu diubah menjadi JSON satu record per baris (`velo-task-2027-03-11.json`). Bentuk keluaran CLI `pyvelociraptor` dan cara ia menerima variabel perlu dicek di versi-mu sebelum skrip konversinya ditulis; yang penting bagi notebook adalah hasil akhirnya, satu record JSON per baris, format yang sama dengan yang dibaca provider `VelociraptorLogs` [S13].

Sel pemuatan dan manifest:

```python
import hashlib
import json

POLA_EXE = r'^"?([^"]+?\.(?:exe|bat|cmd|ps1|vbs|js))'


def muat_velo(pola):
    bagian = []
    for p in sorted(DATA_DIR.glob(pola)):
        d = pd.read_json(p, lines=True)
        d["file"] = p.name
        bagian.append(d)
    return pd.concat(bagian, ignore_index=True)


vr = pd.concat([muat_velo("velo-task-*.json"), muat_velo("velo-startup-*.json")],
               ignore_index=True)
st = vr["Mekanisme"] == "startup"
vr.loc[st, "Path"] = vr.loc[st, "Path"].str.extract(POLA_EXE, flags=2, expand=False)
vr["host"] = host_pendek(vr["Hostname"])
vr["koleksi"] = (pd.to_datetime(vr["Koleksi"]).dt.tz_localize(PARAMS["zona"])
                   .dt.tz_convert("UTC"))

aset = pd.read_csv(DATA_DIR / "jab_assets-2027-04-07.csv")
aset["host"] = host_pendek(aset["nt_host"])
aset["city"] = aset["city"].str.lower()
pop = set(aset.loc[aset["city"].isin(PARAMS["kota_pop"])
                   & (aset["category"] == "workstation"), "host"])


def sha256(path, blok=1 << 20):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for isi in iter(lambda: f.read(blok), b""):
            h.update(isi)
    return h.hexdigest()


manifest = [{"file": p.name, "sha256": sha256(p)} for p in sorted(DATA_DIR.iterdir())]
(OUT_DIR / "manifest.json").write_text(json.dumps(manifest, indent=2))
print(len(vr), vr["host"].nunique(), len(pop))
```

- `flags=2` adalah `re.IGNORECASE`; `str.extract(..., expand=False)` mengembalikan satu kolom berisi path program dari baris perintah StartupItems.
- `Koleksi` ditulis sendiri dalam WIB tanpa offset, sehingga dilokalisasi eksplisit, bukan diurai dengan `utc=True` (bagian 1.6).
- Manifest ditulis ke `out/`, karena ia ikut ke repo; file yang di-hash tetap di `raw/`.

Keluaran ilustrasi, diringkas dari manifest, Job Inspector, dan sel pemuatan:

```
Job Splunk (fw-pop.spl, v2)  SID 1807155012.48877  10:30:12-10:32:10 WIB
  runDuration 117,9 s  scanCount 4.212.604  eventCount 612.447  resultCount 612.447
fw-pop-20270311-20270408.csv.gz          9,6 MB   612.447 baris   duplikat (fw, session_id): 0
velo-task-*.json (4 hunt mingguan)              263.879 baris   1.639 koleksi
velo-startup-*.json (4 hunt mingguan)            37.697 baris   1.639 koleksi
  dari 23 workstation POP: 61 koleksi dari 22 host (9.821 baris task, 1.403 baris startup)
jab_assets-2027-04-07.csv                        443 host  (workstation POP: 23)
pop-dhcp-reservations-2027-04-07.csv             47 baris
```

**Cara membaca hasil:** 612.447 baris di file sama dengan `resultCount` job, dan tidak ada sesi dobel; tarikan itu lengkap. `scanCount` 4.212.604 dalam 117,9 detik adalah sekitar 35.700 event per detik, angka normal untuk platform PT JAB (Day 06 bagian 1.6). Angka di atas milik ekspor versi 2; versi 1 pukul 09:05 (SID `1807149903.48213`, 118,4 detik, `resultCount` sama) diulang karena kesalahan zona waktu di bagian 2.6. Di luar dua job itu, semua langkah berikutnya tidak menyentuh search head. Di sisi Velociraptor, 61 koleksi dari kemungkinan 92 (23 host kali 4 minggu) adalah sifat laptop yang jarang online, bukan kegagalan; `MDN-WS-0019` tidak pernah menjawab karena sedang diservis di vendor sejak awal Maret.

**Variasi:** `jab_assets.csv` adalah lookup Splunk, sehingga bisa diambil dengan `qry.exec_query('| inputlookup jab_assets.csv', timeout=120)` alih-alih file; tetap simpan hasilnya ke `raw/` dan masukkan ke manifest.

**Kapan gagal:** query ekspor memakai `strftime(_time, ...)` tanpa `%z` (bagian 2.6 menunjukkan akibatnya); jumlah baris file tidak dicocokkan dengan `resultCount`, sehingga hasil yang terpotong karena batas halaman tidak terlihat; atau token disalin ke sel untuk "tes cepat" lalu tersimpan di riwayat notebook.

### 2.4 Stacking dan first-seen autostart

Langkah ini adalah sisi host dari hipotesis: entri autostart di lokasi yang bisa ditulis pengguna, di workstation POP, yang langka di seluruh fleet.

**Tujuan:** menormalisasi path dan nama task, merapatkan baris per host, menghitung jumlah host per entri di seluruh fleet, lalu mengambil entri POP yang langka.

```python
POLA_USER = r"\\users\\[^\\]+\\"
POLA_VER = r"\\\d+(?:\.\d+){1,3}\\"
POLA_WRITABLE = r"\\users\\|\\appdata\\|\\programdata\\|\\temp\\"
POLA_SID_GUID = r"-S-1-5-21-[0-9-]+|\{[0-9A-Fa-f-]{36}\}"


def normalisasi_entry(df):
    df = df.copy()
    path = df["Path"].astype("string").str.lower()
    path = path.str.replace(POLA_USER, r"\\users\\<user>\\", regex=True)
    df["path_n"] = path.str.replace(POLA_VER, r"\\<ver>\\", regex=True)
    df["entry_n"] = df["Entry"].astype("string").str.replace(POLA_SID_GUID, "", regex=True)
    df["writable"] = df["path_n"].str.contains(POLA_WRITABLE, regex=True, na=False)
    return df


vr = normalisasi_entry(vr)
kunci_entry = ["Mekanisme", "entry_n", "path_n"]
host_entry = vr.drop_duplicates(subset=["host"] + kunci_entry)

stack = (
    host_entry.groupby(kunci_entry)
              .agg(host_unik=("host", "nunique"),
                   pertama=("koleksi", "min"),
                   terakhir=("koleksi", "max"))
              .reset_index()
              .sort_values(["host_unik"])
)
entri = host_entry.merge(stack[kunci_entry + ["host_unik"]], on=kunci_entry,
                         how="left", validate="many_to_one")

langka = entri[entri["host"].isin(pop) & entri["writable"]
               & (entri["host_unik"] <= PARAMS["ambang_langka"])]
print(len(vr), len(host_entry), len(stack), len(langka), langka["host"].nunique())
```

| Bagian | Fungsi |
|---|---|
| `POLA_USER`, `POLA_VER` | `\users\<nama>\` menjadi `\users\<user>\` dan folder berversi menjadi `\<ver>\`, padanan normalisasi path di Day 05; tanpa ini satu updater per-user terpecah per pengguna dan per versi |
| `POLA_SID_GUID` | Membuang akhiran SID dan GUID di nama task per-user, sama dengan VQL Day 09 bagian 2.4 |
| `drop_duplicates(subset=["host"] + kunci_entry)` | Satu baris per host dan entri, walaupun host itu muncul di empat koleksi mingguan (bagian 1.6) |
| `nunique` | Jumlah host, bukan jumlah baris |
| `validate="many_to_one"` | `stack` harus unik per entri; bila tidak, pandas berhenti, bukan menggandakan baris |
| `langka = ...` | Tiga syarat bernama: host POP, lokasi user-writable, langka di fleet (`ambang_langka` dari parameter) |

Keluaran ilustrasi (statistik):

```
Baris Velociraptor (semua client, 4 minggu)          : 301.576
Host-entry unik (setelah dedup per host)              : 80.215
Entri dinormalisasi di fleet                          : 1.874
Host-entry POP di lokasi user-writable                : 212 (37 entri dinormalisasi)
... dengan host_unik <= 3                             : 6 host-entry di 5 host (5 entri)
```

Keluaran ilustrasi (enam host-entry):

```
host         Mekanisme  entry_n                path_n                                                         host_unik
sby-ws-0112  task       \PrintVendor Cleanup   c:\programdata\printvendor\tools\cleanup.exe                         1
mdn-ws-0013  startup    mapdrive.bat           c:\users\<user>\appdata\roaming\microsoft\windows\start menu\...      1
sby-ws-0115  task       \TenderDocs Sync       c:\users\<user>\appdata\local\tenderdocs\tdsync.exe                  2
sby-ws-0118  task       \TenderDocs Sync       c:\users\<user>\appdata\local\tenderdocs\tdsync.exe                  2
mdn-ws-0013  task       \DocReader Update      c:\users\<user>\appdata\local\programs\docreader\updater.exe         3
mdn-ws-0016  startup    EBankKey Agent         c:\programdata\ebankkey\ebk-agent.exe                                3
```

**Cara membaca hasil:** dari 11.224 baris POP dan 301.576 baris fleet, tinggal enam host-entry. Satu sudah dikenal: alat pembersih driver printer di `SBY-WS-0112` sudah diberi label jinak saat hunt scheduled task Maret (Day 10). Lima sisanya ditinjau di bagian 2.6 bersama data jaringan, karena entri autostart saja tidak berkata apa-apa tentang apa yang dilakukan programnya.

**Uji positif:** fungsi yang sama dijalankan atas koleksi `SBY-WS-0107` dari Kamis 2027-02-25 yang masih tersimpan di `jkt-velo02` sebagai bagian `INC-2027-040`. `\PDFSuite Updater` dengan `c:\users\<user>\appdata\local\pdfsuite\pdfupdater.exe` muncul dengan `host_unik` 1. Filter ini sanggup menangkap pola yang pernah benar-benar terjadi di PT JAB.

First-seen dengan dua jendela, pola yang sama dengan first-seen di Day 05 dan Day 06 tetapi di pandas. Untuk snapshot mingguan, "baru" berarti entri yang muncul di koleksi terakhir dan tidak ada di koleksi sebelumnya dari host yang sama:

```python
def first_seen(df, kunci, kolom_waktu, batas, awal=None):
    mask_lama = df[kolom_waktu] < batas
    if awal is not None:
        mask_lama &= df[kolom_waktu] >= awal
    lama = df.loc[mask_lama, kunci].drop_duplicates()
    baru = df.loc[df[kolom_waktu] >= batas]
    tanda = baru.merge(lama, on=kunci, how="left", indicator=True)
    return (tanda[tanda["_merge"] == "left_only"]
              .groupby(kunci)
              .agg(pertama=(kolom_waktu, "min"), jumlah=(kolom_waktu, "size"))
              .sort_values("jumlah", ascending=False))


batas = SELESAI - pd.Timedelta(days=PARAMS["jendela_baru_hari"])
awal = batas - pd.Timedelta(days=PARAMS["baseline_hari"])
host_lama = set(vr.loc[(vr["koleksi"] < batas) & (vr["koleksi"] >= awal), "host"])
vr_pop = vr[vr["host"].isin(pop & host_lama)]
baru = first_seen(vr_pop, ["host"] + kunci_entry, "koleksi", batas, awal)
print(len(baru))
```

- `indicator=True` lalu `_merge == "left_only"` adalah anti-join: baris baru yang tidak punya pasangan di baseline [S18]. Logika first-seen seluruhnya ada di dua baris itu.
- `batas` dan `awal` diambil dari sel parameter, bukan ditulis ulang di tiap sel. Dengan `SELESAI` 8 April, `batas` jatuh pada 1 April 00:00 WIB (koleksi terakhir) dan `awal` pada 11 Maret 00:00 WIB.
- `host_lama` membatasi ke host yang punya koleksi di baseline. Tanpa itu, laptop yang baru pertama kali online pada 1 April akan membuat semua entrinya terlihat baru.

Keluaran ilustrasi:

```
host-entry baru di koleksi 2027-04-01 (host yang juga punya koleksi baseline): 2
  mdn-ws-0013  startup  mapdrive.bat        pertama 2027-04-01
  mdn-ws-0013  task     \DocReader Update   pertama 2027-04-01
Tanpa normalisasi <ver>                                                       : 12
```

**Cara membaca hasil:** dua entri baru, keduanya di `MDN-WS-0013`, yang juga muncul di daftar langka. Tanpa normalisasi `<ver>`, sepuluh updater yang hanya berganti folder versi ikut terlihat baru. Angka 12 dan 2 dicatat di laporan sebagai bukti bahwa normalisasi membuang derau, bukan sinyal.

**Kapan gagal:** bila baseline-nya terlalu pendek, semua terlihat baru. Jalankan dengan dua nilai `baseline_hari` yang berbeda dan bandingkan jumlah barisnya sebelum memeriksa isinya. Untuk snapshot, "pertama" adalah tanggal koleksi, bukan tanggal entri dibuat; waktu pembuatan hanya ada di `RegistrationTime` task.

### 2.5 Interval beacon dengan pandas

Langkah ini adalah sisi jaringan hipotesis, dan alasan utama hunt ini pindah ke notebook: ambang bisa dicoba berkali-kali tanpa menjalankan ulang search 28 hari.

**Tujuan:** memetakan IP sumber ke host, lalu menjalankan dua tahap yang sama dengan program hunt (tahap A prevalence dan jumlah koneksi, tahap B keteraturan interval setelah jeda panjang dibuang) atas sesi firewall POP.

Pemetaan IP ke host lebih dulu, karena firewall hanya mencatat IP dan workstation POP memakai reservasi DHCP:

```python
fw = pd.read_csv(DATA_DIR / "fw-pop-20270311-20270408.csv.gz")
print("baris:", len(fw), "duplikat sesi:", fw.duplicated(subset=["fw", "session_id"]).sum())
fw = normalisasi(fw, kolom_waktu="epoch", unit="s")
fw["start"] = fw["epoch"] - pd.to_timedelta(fw["duration"], unit="s")

dhcp = pd.read_csv(DATA_DIR / "pop-dhcp-reservations-2027-04-07.csv")
dhcp["host"] = host_pendek(dhcp["nt_host"])
fw = fw.merge(dhcp[["ip", "host"]], left_on="src", right_on="ip", how="left",
              validate="many_to_one", indicator="peta")
print(fw["peta"].value_counts())
sesi_ws = fw[fw["peta"] == "both"]
```

Percobaan pertama berhenti di `merge` dengan `MergeError`: kunci di sisi kanan tidak unik. Daftar reservasi memuat 47 baris, dan `10.50.12.19` muncul dua kali: untuk `MDN-WS-0019` (laptop yang sedang diservis) dan `MDN-WS-0021` (laptop cadangan Medan yang menerima reservasi itu sejak Senin 2027-03-22). Tanpa `validate`, setiap sesi dari IP itu akan tergandakan dan diberi dua nama host. NOC mengonfirmasi bahwa baris lama tertinggal di ekspor; setelah baris `MDN-WS-0019` dibuang, daftar berisi 46 baris (23 host, masing-masing reservasi LAN dan Wi-Fi), dan sesi dari IP itu sebelum 22 Maret berjumlah nol.

Keluaran ilustrasi setelah perbaikan:

```
baris: 612447 duplikat sesi: 0
peta
both         609118
left_only      3329
```

**Cara membaca hasil:** 609.118 sesi terpetakan ke 19 workstation POP; 3.329 sesi dari 4 IP tidak punya pasangan: dua printer multifungsi, satu perekam CCTV, dan satu pengendali Wi-Fi di kantor POP. Perangkat itu bukan workstation dan di luar cakupan hipotesis, tetapi jumlahnya dicetak dan dicatat, karena "baris yang tidak berpasangan" adalah angka yang mengungkap masalah normalisasi paling cepat. Empat workstation POP tidak punya satu sesi kantor pun selama 28 hari (`MDN-WS-0019` dan tiga laptop yang hanya bekerja dari luar kantor); untuk keempatnya, sisi jaringan hunt ini berstatus data tidak cukup.

Fungsi deteksi beacon, ditulis sekali dan dipakai untuk data nyata maupun uji positif:

```python
def deteksi_beacon(sesi, P):
    kunci = ["host", "dest", "dest_port"]
    sesi = sesi.assign(jam=sesi["start"].dt.floor("h"))
    pasangan = (sesi.groupby(kunci)
                    .agg(conns=("start", "size"), hours_seen=("jam", "nunique"),
                         first_seen=("start", "min"))
                    .reset_index())
    pasangan["dest_hosts"] = pasangan.groupby("dest")["host"].transform("nunique")
    tahap_a = pasangan[(pasangan["dest_hosts"] <= P["max_dest_hosts"])
                       & (pasangan["conns"] >= P["min_conns"])
                       & (pasangan["hours_seen"] >= P["min_hours"])]

    conn = sesi.merge(tahap_a[kunci], on=kunci).sort_values(kunci + ["start"])
    conn["delta"] = conn.groupby(kunci)["start"].diff().dt.total_seconds()
    conn = conn.dropna(subset=["delta"])
    conn["med_int"] = conn.groupby(kunci)["delta"].transform("median")
    conn = conn[conn["delta"] <= P["gap_factor"] * conn["med_int"]]

    ringkas = (conn.groupby(kunci)
                   .agg(intervals=("delta", "size"), avg_int=("delta", "mean"),
                        sd_int=("delta", "std"), med_int=("med_int", "max"),
                        avg_bytes_out=("bytes_out", "mean"))
                   .reset_index())
    ringkas["cv"] = (ringkas["sd_int"] / ringkas["avg_int"]).round(3)
    lolos = ringkas[ringkas["med_int"].between(P["med_min"], P["med_max"])
                    & (ringkas["cv"] <= P["cv_max"])]
    return tahap_a, lolos.merge(tahap_a, on=kunci)


tahap_a, beacon = deteksi_beacon(sesi_ws, PARAMS)
print(len(tahap_a), len(beacon))
```

| Bagian | Fungsi |
|---|---|
| `start = epoch - duration` | Log akhir sesi dicatat saat sesi selesai; waktu mulai dihitung dari durasi (detik), sama dengan `start=_time-duration` di Day 12 bagian 2.1 |
| `dt.floor("h")` lalu `nunique` | `hours_seen`: berapa jam berbeda pasangan itu terlihat |
| `transform("nunique")` per `dest` | Prevalence tujuan dihitung dari semua pasangan, lalu dipasang ke tiap baris |
| `groupby(kunci)["start"].diff()` | Selisih antar sesi berurutan di dalam pasangan; baris pertama tiap pasangan kosong dan dibuang [S19] |
| `transform("median")` lalu `delta <= gap_factor * med_int` | Jeda malam, akhir pekan, dan laptop dibawa pulang dibuang dengan median, seperti `eventstats median()` di SPL |
| `std()` | Deviasi standar sampel, sebanding dengan `stdev()` di SPL |
| `cv <= cv_max` dan `med_int` 30 sampai 14.400 detik | Ambang program: CV maksimal 0,2 setelah jeda lebih dari tiga kali median dibuang, interval 30 detik sampai 4 jam (Day 12 bagian 1.4) |

Keluaran ilustrasi (statistik):

```
Pasangan host-dest-port dari 19 host                   : 7.906
Lolos tahap A (dest_hosts <= 10, conns >= 20, hours >= 12): 214
Lolos tahap B (30 s <= med_int <= 4 jam, CV <= 0,2)      : 7 pasangan di 3 tujuan
```

Keluaran ilustrasi (tujuh pasangan, waktu ditampilkan dalam WIB):

```
host         dest            dest_port  conns  hours_seen  med_int  cv     avg_bytes_out  dest_hosts  first_seen
sby-ws-0109  203.0.113.87          443    214         205     3600  0.011            612           4  2027-03-11 08:31
sby-ws-0113  203.0.113.87          443    168         161     3600  0.012            608           4  2027-03-12 08:47
mdn-ws-0012  203.0.113.87          443    131         127     3600  0.013            615           4  2027-03-11 09:02
mdn-ws-0017  203.0.113.87          443     97          94     3600  0.010            611           4  2027-03-15 08:20
sby-ws-0115  198.51.100.164        443    236         119     1800  0.048           2210           2  2027-03-15 09:14
sby-ws-0118  198.51.100.164        443    181          92     1800  0.052           2204           2  2027-03-16 13:07
mdn-ws-0016  198.51.100.140       8443   1412         236      600  0.031            944           1  2027-03-11 08:02
```

**Cara membaca hasil:** tujuh pasangan, tiga tujuan, tidak ada yang dihubungi lebih dari empat host. Firewall tidak memberi nama proses maupun nama domain; dua-duanya dicari di bagian 2.6 lewat join dengan entri autostart dan satu search kecil ke `index=dns`. Iterasi ambang (CV 0,15, 0,2, dan 0,25; `min_conns` 10 dan 20; `gap_factor` 3 dan 5) dijalankan di notebook, masing-masing 4 sampai 7 detik, tanpa satu pun job tambahan di search head. Hanya CV 0,25 yang menambah pasangan, yaitu dua laptop yang menyinkronkan klien rapat dengan interval tidak rapi, dan ambang program tetap 0,2.

**Uji positif sintetis:** bukti bahwa fungsi ini sanggup menangkap beacon berjitter, dibuat tanpa menjalankan apa pun di endpoint. Deret 200 koneksi buatan dengan interval 300 detik plus minus 20% disisipkan ke salinan data:

```python
import numpy as np

rng = np.random.default_rng(32)
t0 = pd.Timestamp("2027-03-16 08:00", tz=PARAMS["zona"]).tz_convert("UTC")
jeda = rng.uniform(0.8, 1.2, size=200) * 300
uji = pd.DataFrame({
    "host": "uji-sintetis", "dest": "192.0.2.250", "dest_port": 443, "bytes_out": 512,
    "start": t0 + pd.to_timedelta(jeda.cumsum(), unit="s"),
})
_, hasil_uji = deteksi_beacon(pd.concat([sesi_ws, uji], ignore_index=True), PARAMS)
print(hasil_uji.loc[hasil_uji["host"] == "uji-sintetis", ["intervals", "med_int", "cv"]])
```

Keluaran ilustrasi: `intervals` 199, `med_int` 301, `cv` 0,118. Secara teori jitter seragam plus minus 20% memberi CV sekitar 0,115 (Day 12 bagian 1.4), jadi angka itu masuk akal, dan deret itu lolos semua syarat. Deret uji tidak pernah ditulis ke file hasil.

**Variasi:** grafik sebaran `cv` terhadap `conns` untuk 214 pasangan tahap A memperlihatkan bentuk data: kelompok rapat di CV di bawah 0,05 (agent perangkat), kelompok lebar di atas 0,5 (aktivitas pengguna), dan sedikit pasangan di antaranya. Ambang dipilih dari bentuk itu, bukan dari tebakan. Untuk beacon dengan jitter besar, tambahkan pemeriksaan modus interval yang dibulatkan (`conn.groupby(kunci)["delta"].agg(lambda s: s.round(-1).mode().iloc[0])`), bukan hanya rata-rata.

**Kapan gagal:** jitter yang disengaja di atas sekitar 35% membuat `sd` besar dan beacon lolos; beacon dengan interval di atas 4 jam; laptop yang tidak pernah ke kantor; C2 dalam satu sesi panjang (satu baris firewall, tanpa interval); dan reservasi DHCP yang usang, yang memberi nama host salah tanpa error bila `validate` tidak dipasang.

### 2.6 Join lintas sumber dan pelajaran zona waktu

Join ini adalah alasan hunt dikerjakan di notebook: tujuh pasangan beacon dari firewall dipertemukan dengan entri autostart dari Velociraptor dan konteks dari daftar aset.

**Tujuan:** untuk setiap pasangan beacon, cari entri autostart di host yang sama yang bisa menjelaskannya, dan tandai pasangan yang tidak punya penjelasan.

```python
konteks = entri[entri["writable"] & (entri["host_unik"] <= PARAMS["ambang_konteks"])]

beacon_aset = beacon.merge(aset[["host", "city", "ou"]], on="host", how="left",
                           validate="many_to_one")
gabung = beacon_aset.merge(
    konteks[["host", "Mekanisme", "Entry", "path_n", "host_unik", "RegistrationTime"]],
    on="host", how="left", validate="many_to_many")

tanpa_pasangan = gabung[gabung["path_n"].isna()]
print(f"{len(gabung)} baris dari {len(beacon)} pasangan; "
      f"{len(tanpa_pasangan)} pasangan beacon tanpa entri autostart yang bisa menjelaskan")

reg = pd.to_datetime(gabung["RegistrationTime"], utc=True, errors="coerce")
gabung["selisih"] = gabung["first_seen"] - reg
print(gabung.loc[reg.notna(), ["host", "Entry", "first_seen", "selisih"]])
```

- `how="left"` sengaja dipilih supaya pasangan beacon tanpa entri autostart tetap terlihat. Di hunting, yang tidak punya pasangan sering lebih menarik daripada yang punya.
- `validate="many_to_one"` untuk aset (satu host satu baris di `jab_assets.csv`), `validate="many_to_many"` untuk entri autostart. Yang kedua tidak memeriksa apa-apa [S18]; ia ditulis supaya pembaca tahu penggandaan baris di join itu disengaja (satu host bisa punya beberapa entri), dan jumlah baris sebelum dan sesudah dicetak.
- `ambang_konteks` 10 lebih longgar dari `ambang_langka` 3: untuk menjelaskan beacon, entri yang dipakai beberapa host tetap berguna.
- `selisih` membandingkan waktu task didaftarkan (Velociraptor, UTC) dengan sesi pertama ke tujuan beacon (firewall). Selisih pendek menguatkan bahwa program dari task itulah yang menghubungi tujuan tersebut.

**Pelajaran zona waktu.** Run pertama sel ini, pukul 10:25, memberi hasil yang terlihat masuk akal:

```
host         Entry              first_seen (WIB)     selisih
sby-ws-0115  \TenderDocs Sync   2027-03-15 16:14     0 days 07:01:23
sby-ws-0118  \TenderDocs Sync   2027-03-16 20:07     0 days 07:01:48
```

Dua hal tidak cocok. Selisih di kedua host hampir persis tujuh jam lebih satu menit, padahal updater biasanya menghubungi servernya beberapa saat setelah terpasang. Profil per jam sesi kantor POP juga aneh: 81% sesi tercatat antara 15:00 dan 23:59 WIB, seakan staf POP bekerja sampai tengah malam, dan pada laptop yang menyala malam hari beacon sah dan beacon jahat sama-sama terlihat seperti "aktif saat pengguna tidak ada". Penyebabnya ada di ekspor versi pertama, sebelum query di bagian 2.3 diperbaiki: query itu disalin dari panel dashboard dan memuat `eval waktu=strftime(_time, "%Y-%m-%d %H:%M:%S")` tanpa `%z`. Teks WIB tanpa offset itu lalu diurai dengan `pd.to_datetime(fw["waktu"], utc=True)`, yang menganggapnya UTC [S15]. Semua sesi bergeser tujuh jam ke depan, tanpa satu error pun.

Pemeriksaan yang mengonfirmasinya murah: satu search kecil untuk satu IP dan setengah jam, yang mencetak waktu dengan offset.

```python
kontrol = qry.exec_query(
    'search index=firewall sourcetype=pan:traffic eventtype=pan_traffic_end host=sby-fw01 '
    'src=10.40.12.115 dest=198.51.100.164 '
    'earliest="03/15/2027:09:00:00" latest="03/15/2027:09:30:00" '
    '| stats min(_time) AS t_min count '
    '| eval t_min_teks=strftime(t_min, "%Y-%m-%d %H:%M:%S %z")',
    timeout=120)
print(kontrol)
```

Keluaran ilustrasi: `t_min` 1805076843, `t_min_teks` "2027-03-15 09:14:03 +0700". Sesi pertama terjadi 09:14 WIB, bukan 16:14. Perbaikannya ada di dua tempat yang sudah terlihat di bagian 2.2 dan 2.3: query mengekspor `epoch`, dan `normalisasi()` kini menolak teks waktu tanpa zona. Setelah ekspor ulang (satu job lagi pukul 10:30, SID `1807155012.48877`, 117,9 detik, dicatat di manifest sebagai versi 2 dengan alasan; file versi 1 diberi akhiran `-v1` dan ditandai tidak dipakai), hasilnya:

```
host         Entry              first_seen (WIB)     selisih
sby-ws-0115  \TenderDocs Sync   2027-03-15 09:14     0 days 00:01:23
sby-ws-0118  \TenderDocs Sync   2027-03-16 13:07     0 days 00:01:48
```

Profil per jam berubah menjadi 83% sesi antara 08:00 dan 16:59 WIB. Interval dan CV di bagian 2.5 tidak berubah, karena pergeseran konstan tidak mengubah selisih antar sesi; yang berubah adalah semua kesimpulan yang bergantung pada jam dan tanggal: urutan task dan koneksi, pola jam kerja, dan pengelompokan per hari (sesi setelah pukul 17:00 WIB sempat pindah ke tanggal berikutnya). Pelajaran ini masuk laporan sebagai baris "Higiene data", karena hunt berikutnya yang menyalin query dari dashboard akan membuat kesalahan yang sama.

Hasil join lengkap setelah perbaikan, satu baris per pasangan beacon:

```
host         dest            entri yang menjelaskan                          host_unik  city
sby-ws-0109  203.0.113.87    startup ModemDash  c:\users\<user>\appdata\local\modemdash\mdash.exe   5  surabaya
sby-ws-0113  203.0.113.87    startup ModemDash  (sama)                                              5  surabaya
mdn-ws-0012  203.0.113.87    startup ModemDash  (sama)                                              5  medan
mdn-ws-0017  203.0.113.87    startup ModemDash  (sama)                                              5  medan
sby-ws-0115  198.51.100.164  task \TenderDocs Sync  ...\tenderdocs\tdsync.exe                       2  surabaya
sby-ws-0118  198.51.100.164  task \TenderDocs Sync  (sama)                                          2  surabaya
mdn-ws-0016  198.51.100.140  startup EBankKey Agent  c:\programdata\ebankkey\ebk-agent.exe          3  medan
7 baris dari 7 pasangan; 0 pasangan beacon tanpa entri autostart yang bisa menjelaskan
```

Setiap kaitan lalu dikonfirmasi di luar notebook, karena join hanya menunjukkan bahwa entri dan beacon ada di host yang sama:

- **`203.0.113.87`, ModemDash.** Search kecil ke `index=dns` dari IP keempat laptop menunjukkan query ke `api.modemdash.example` beberapa detik sebelum tiap sesi. ModemDash adalah aplikasi dashboard modem USB dari vendor seluler yang dipasang bersama modem untuk laptop sales POP; hunt autoruns Februari sudah melihatnya di satu laptop sales Medan (Day 09), dan kini terlihat di lima host karena cakupan Velociraptor POP membaik. Host kelima, `MDN-WS-0014`, tidak pernah di kantor selama 28 hari. Dikonfirmasi tim IT End User Computing. Label: jinak.
- **`198.51.100.164`, TenderDocs.** `IoCExtract` atas kolom `Arguments` task menarik `https://sync.tenderdocs.example` (bagian 2.7), dan `index=dns` mencocokkan domain itu dengan IP tersebut. TenderDocs adalah klien portal tender milik pelanggan korporat yang dipasang per pengguna oleh dua sales Surabaya, `bayu.saputra` (`SBY-WS-0115`) dan `wulan.pertiwi` (`SBY-WS-0118`), lewat permintaan software yang disetujui IT pada 12 Maret; binary-nya bertanda tangan vendor. Selisih satu sampai dua menit antara pendaftaran task dan sesi pertama cocok dengan pemasangan. Label: jinak.
- **`198.51.100.140:8443`, EBankKey.** Agent token perbankan dari bank mitra (`ebk.bankmitra.example`) di laptop staf Keuangan POP Medan `MDN-WS-0016` (`sinta.marpaung`), mengirim heartbeat tiap 600 detik. Dua host lain yang punya entri sama adalah workstation Keuangan Jakarta. Dipasang teknisi bank lewat tiket Keuangan Januari 2027, dikonfirmasi tim Keuangan dan IT. Label: jinak.

Kandidat autostart dari bagian 2.4 yang tidak punya beacon juga diberi label: `\PrintVendor Cleanup` di `SBY-WS-0112` (sudah dikenal, alat driver printer, bertanda tangan); `mapdrive.bat` dan `\DocReader Update` di `MDN-WS-0013`, keduanya dipasang Rahmat Nasution (IT lokal POP Medan) pada 29 dan 30 Maret saat menyiapkan laptop itu untuk karyawan baru, sesuai tiket. Skrip `mapdrive.bat` hanya memetakan share internal, dan updater pembaca dokumen berasal dari katalog self-service IT. Label: jinak.

**Variasi, identitas.** Pola join yang sama dipakai untuk pertanyaan identitas: akun yang melakukan logon jaringan ke host yang tidak pernah ia akses sebelumnya, dan pada hari yang sama tercatat sign-in dari ASN baru di log identitas (Day 17).

```python
logon = normalisasi(pd.read_json(DATA_DIR / "logon.json", lines=True))
signin = normalisasi(pd.read_json(DATA_DIR / "signin.json", lines=True))
signin["user"] = signin["user"].str.split("@").str[0]

logon["tanggal"] = logon["timestamp"].dt.tz_convert(PARAMS["zona"]).dt.date
signin["tanggal"] = signin["timestamp"].dt.tz_convert(PARAMS["zona"]).dt.date

gabung_id = logon.merge(
    signin[["user", "tanggal", "asn", "ip"]].drop_duplicates(),
    on=["user", "tanggal"], how="left", suffixes=("_logon", "_signin"))

tanpa_signin = gabung_id[gabung_id["asn"].isna()]
print(f"{len(tanpa_signin)} logon tanpa sign-in padanan pada hari yang sama")
```

- Baris `print` terakhir adalah kebiasaan yang layak dipakai di tiap join: selalu laporkan berapa baris yang tidak berpasangan.
- `tz_convert(PARAMS["zona"])` sebelum `.dt.date`: tanpa itu tanggal diambil dari UTC, dan logon pukul 06:30 WIB masuk tanggal kemarin, sehingga dipasangkan dengan sign-in hari yang salah.
- `drop_duplicates()` di sisi sign-in mencegah satu logon berubah menjadi puluhan baris karena satu pengguna sign-in berkali-kali sehari.

**Kapan gagal:** nama akun berbeda format antar sumber, misalnya `rani.oktaviani` di log Windows dan `rani.oktaviani@jab.example` di sign-in Entra, atau nama host pendek di satu sumber dan FQDN di sumber lain. Samakan di sel normalisasi (seperti `host_pendek()` dan `split("@")` di atas), bukan di sel join. Kegagalan lain: menganggap kaitan entri dan beacon di host yang sama sebagai bukti, padahal tanpa nama proses itu hanya dugaan yang harus dikonfirmasi.

### 2.7 MSTICPy untuk pengayaan, dan apa yang tidak dijalankan di nb01

Pertanyaan keempat Dimas dijawab dengan apa yang benar-benar dipakai di hunt ini dan apa yang sengaja tidak dipakai.

**Tujuan:** menarik indikator dari kolom teks kandidat tanpa menulis regex sendiri, dan memisahkan pengayaan yang aman dijalankan di VM dari yang butuh layanan luar.

```python
ioc = mp.IoCExtract()
kandidat_teks = langka.merge(vr[["host"] + kunci_entry + ["Arguments"]].drop_duplicates(),
                             on=["host"] + kunci_entry, how="left")
indikator = ioc.extract(data=kandidat_teks, columns=["path_n", "Arguments"],
                        ioc_types=["url", "dns", "ipv4"])
print(indikator[["IoCType", "Observable", "SourceIndex"]])
```

- `ioc_types` membatasi tipe yang dicari; tanpa itu path dan hash ikut diekstrak, padahal untuk DataFrame tipe path memang dikecualikan secara bawaan [S11].
- `SourceIndex` menunjuk ke baris asal di `kandidat_teks`, sehingga indikator bisa dikembalikan ke host dan entrinya [S11].
- Seluruh proses berjalan lokal.

Keluaran ilustrasi:

```
IoCType  Observable                          SourceIndex
url      https://sync.tenderdocs.example     2
dns      sync.tenderdocs.example             2
url      https://sync.tenderdocs.example     3
dns      sync.tenderdocs.example             3
```

**Cara membaca hasil:** satu-satunya indikator jaringan di argumen kandidat adalah server TenderDocs, dan itulah yang menghubungkan task di bagian 2.4 dengan beacon di bagian 2.5. Tiga domain beacon (`api.modemdash.example`, `sync.tenderdocs.example`, `ebk.bankmitra.example`) dan dua IP-nya dicek ke threat intelligence ES lewat pencarian IOC biasa oleh L1, dengan hasil tidak ada kecocokan. Reputasi bersih bukan bukti aman; label jinak di atas bertumpu pada konfirmasi pemilik dan tiket.

Yang tidak dijalankan di nb01, dan bentuknya bila dijalankan di lab pribadi dengan data publik:

```python
ti = mp.TILookup(providers=["OTX"])
hasil_ti = ti.lookup_iocs(data=indikator_eksternal, ioc_col="Observable",
                          ioc_type_col="IoCType")

from msticpy.datamodel.entities import IpAddress
whois = IpAddress.util.whois(data=ip_eksternal, column="Observable", join="left")
```

- `TILookup(providers=[...])` hanya memuat provider yang disebut; tanpa argumen ia memuat semua provider yang ada di konfigurasi [S9].
- `ioc_col` dan `ioc_type_col` adalah nama argumen di kode `lookup_iocs()` saat ini [S10]. Versi lama Day ini menulis `obs_col`, yang tidak ada di kode MSTICPy sekarang.
- `IpAddress.util.whois(data=..., column=...)` adalah bentuk pivot dengan DataFrame dari dokumentasi [S12]; jalur impor entitas `msticpy.datamodel.entities` perlu dicek di versi-mu, karena `init_notebook()` juga menyediakan entitas lewat atribut pivot.
- Dua fungsi itu menghubungi layanan di luar jaringan. Di nb01 tidak ada provider yang dikonfigurasi dan tidak ada akses internet, jadi keduanya hanya untuk lab.

Untuk hasil Velociraptor yang tersedia sebagai file JSON (misalnya koleksi offline dari laptop POP yang dikirim lewat manajer POP), provider `VelociraptorLogs` menggantikan `muat_velo()`:

```python
vc = mp.QueryProvider("VelociraptorLogs", data_paths=[str(DATA_DIR / "velo-offline")])
vc.connect()
print(vc.list_queries())
```

- File baru dibaca saat query tabel dijalankan, bukan saat `connect()`, dan nama tabel diawali `velociraptor.` [S13]. Cek jalur akses tabelnya di versi-mu, karena contoh di dokumentasi tidak seragam.
- Fungsi query provider ini tidak memfilter apa pun [S13], jadi normalisasi dan penyaringan tetap memakai sel di bagian 2.2 dan 2.4.

**Kapan gagal:** versi MSTICPy berubah dan nama fungsi ikut berubah. Kunci versinya di sel versi dan catat di laporan hunt [S2]. Kegagalan lain: `init_notebook()` di mesin tanpa internet mencoba memeriksa atau mengunduh sesuatu dan berhenti lama; jalankan sekali saat memasang dan catat peringatannya.

### 2.8 Laporan `HUNT-2027-032`, artefak di repo, dan balasan untuk Dimas

Laporan ini menutup hunt dengan format Day 07 bagian 1.9, ditambah baris lingkungan dan higiene data.

```
ID            : HUNT-2027-032                                   Selesai: Kamis 2027-04-08 16:30
Hasil         : Tidak ditemukan aktivitas berbahaya
Lingkungan    : jkt-hunt-nb01; notebook HUNT-2027-032.ipynb (Python 3.12.11, pandas 2.3.3,
                MSTICPy 3.1.0, JupyterLab 4.6.4)
Cakupan nyata : Keadaan host: 22 dari 23 workstation POP (61 koleksi Velociraptor dari 4 hunt
                mingguan 11 Mar - 1 Apr 2027), dibandingkan dengan 1.639 koleksi seluruh fleet.
                Jaringan: 19 dari 23 workstation POP saat di kantor (sby-fw01, mdn-fw01),
                11 Mar - 8 Apr 2027 WIB, 612.447 sesi ke tujuan eksternal.
                Di luar cakupan: laptop saat di luar kantor (split tunnel); MDN-WS-0019 (servis);
                3 laptop tanpa sesi kantor selama 28 hari (sisi jaringan: data tidak cukup);
                autostart lewat service dan WMI; interval > 4 jam; tujuan dengan dest_hosts > 10
Ambang        : host_unik <= 3 (kandidat), <= 10 (konteks); CV <= 0,2 setelah jeda > 3x median
                dibuang; 30 s <= median <= 4 jam; conns >= 20; hours_seen >= 12
Kelengkapan   : resultCount 612.447 = baris file; duplikat sesi 0; 3.329 sesi dari 4 perangkat
                non-workstation tanpa reservasi (di luar cakupan); uji positif: PDFSuite (host),
                deret sintetis 300 s +-20% (jaringan, CV 0,118)
Jinak terkonfirmasi : ModemDash di 4 host (dashboard modem USB vendor seluler); TenderDocs di
                SBY-WS-0115 dan SBY-WS-0118 (permintaan software 12 Mar); EBankKey di MDN-WS-0016
                (agent bank mitra, tiket Keuangan Jan 2027); PrintVendor Cleanup SBY-WS-0112;
                mapdrive.bat dan DocReader Update di MDN-WS-0013 (IT lokal, 29-30 Mar)
Higiene data  : Ekspor v1 memakai strftime tanpa offset; WIB terbaca sebagai UTC (geser 7 jam).
                Diperbaiki: ekspor epoch, normalisasi menolak waktu tanpa zona. Reservasi DHCP
                memuat IP ganda (10.50.12.19); tertangkap validate="many_to_one"
Data ekspor   : Manifest 12 file (SHA-256, baris, query; firewall v1 SID 1807149903.48213 ditandai
                tidak dipakai, v2 SID 1807155012.48877);
                raw/ dihapus paling lambat Jumat 2027-04-23 (14 hari setelah persetujuan)
Rekomendasi   : (1) Laporan mingguan terjadwal "TH - kandidat beacon firewall POP" (tahap A dan B
                dalam SPL, Kamis 06:00, schedule_window) -> Sari Kusuma, bukan alert
                (2) Ekspor reservasi DHCP POP dari konfigurasi router, bukan dari spreadsheet;
                log lease DHCP untuk subnet POP -> NOC (Bambang Hartono)
                (3) Tiga tujuan ditambahkan ke jab_hunt_baseline_beacon.csv dengan nama domain,
                IP, pemilik, interval, dan tanggal review
Artefak       : jab-hunt/hunts/HUNT-2027-032/: notebook tanpa output, queries/ (fw-pop.spl,
                velo-task.vql, velo-startup.vql), notebook/manifest.json, notebook/kandidat.csv
                (13 baris berlabel), report.md
Hipotesis baru: (1) host dengan entri autostart yang hilang di antara dua koleksi mingguan
                (dipasang lalu dihapus); (2) laptop POP tanpa sesi kantor > 30 hari -> backlog
```

"Tidak ditemukan" di laporan ini punya cakupan yang dibagi dua sisi (host dan jaringan), karena keduanya berbeda: 22 host untuk keadaan host, 19 untuk jaringan. Pembaca yang hanya melihat angka 23 akan mengira semuanya diperiksa dua kali.

Balasan untuk Dimas dikirim Kamis 17:00, dengan tembusan ke Reza dan Agus untuk baris yang menyangkut mereka. Setiap baris merujuk subbagian di atas.

| Pertanyaan | Jawaban singkat | Dasar |
|---|---|---|
| Kapan notebook, kapan Splunk | Notebook untuk join lintas sumber, statistik di luar SPL, dan banyak ambang; persempit di Splunk, tarik sekali, iterasi lokal. Dua job sekitar 118 detik untuk `-032` (satu diulang karena perbaikan zona waktu), semua iterasi di VM (untuk Reza) | Bagian 1.1, 2.3, 2.5 |
| Bisa diulang dan diaudit | Sel parameter tunggal, sel versi, manifest dengan SHA-256 dan jumlah baris yang cocok dengan `resultCount`, dijalankan dari atas; papermill untuk menjalankan ulang | Bagian 1.2, 2.2, 2.3 |
| Apa yang dikerjakan di notebook | Lima operasi pandas atas sumber berbeda skema; contohnya join beacon firewall dengan autostart Velociraptor | Bagian 1.3, 2.6 |
| MSTICPy dan data keluar | Pengambilan Splunk/Velociraptor dan IoCExtract lokal; TILookup dan whois mengirim indikator keluar, tidak dikonfigurasi di nb01 | Bagian 1.4, 2.7 |
| Data apa, di mana, berapa lama (untuk Agus) | Hanya field dan rentang di abstract; disk terenkripsi nb01, akses dua hunter; mentah dihapus 14 hari setelah laporan disetujui, maksimal 30 hari setelah ekspor | Bagian 1.5 |
| Salah jam dan baris dobel | Waktu sebagai epoch, normalisasi menolak waktu tanpa zona, hitung host bukan baris, `merge` dengan `validate`; hari ini keduanya tertangkap sebelum kesimpulan | Bagian 1.6, 2.5, 2.6 |
| Kembali ke `jab-hunt` | Notebook tanpa output, query, manifest, ringkasan kandidat, laporan; bagian stabil jadi scheduled search | Bagian 1.7 |

**Kapan gagal:** balasan ke Agus hanya berisi "datanya aman di VM terenkripsi". DPO perlu tahu apa yang diekspor, siapa yang bisa membuka, kapan dihapus, dan pengecualiannya; enkripsi disk hanya menjawab satu dari empat.

## 3. Lab praktik (di VM lab terisolasi)

**Prasyarat:** VM lab dengan Python 3.12 dalam virtual environment, JupyterLab 4.6, pandas 2.3.3, MSTICPy 3.1.0 (dengan `msticpy[splunk]` bila lab-mu punya Splunk), papermill, dan nbstripout. Data dari lab pribadimu sendiri (Splunk lab dengan Sysmon atau log firewall lab, hasil koleksi Velociraptor dari VM Windows lab) atau dataset publik dari Day 04. Jangan memakai data dari pekerjaan, dan jangan memuat log pekerjaan atau klien ke notebook yang disimpan di repo catatan ini.

1. **Templat.** Bangun kerangka notebook bagian 2.2 sebagai templat, simpan sebagai `templat-hunt.ipynb`, beri tag `parameters` pada sel parameter, dan pastikan tidak ada angka ajaib di luar sel parameter. Jalankan dua kali dengan papermill (`papermill templat-hunt.ipynb run-a.ipynb -p cv_max 0.2` dan `-p cv_max 0.25`), lalu bandingkan kedua output.
2. **Jebakan parameter.** Tambahkan satu nilai turunan di sel parameter (misalnya batas jendela yang dihitung dari tanggal selesai), jalankan papermill dengan tanggal lain, dan catat bahwa nilai turunan itu tidak berubah. Pindahkan turunannya ke sel berikutnya dan ulangi.
3. **Stacking.** Muat satu dataset proses atau autostart dan jalankan stacking bagian 2.4. Bandingkan hasilnya dengan stacking yang sama di SIEM (Day 06), lalu catat berapa lama masing-masing dan mana yang lebih nyaman diiterasi.
4. **First-seen.** Jalankan first-seen dengan `baseline_hari` bernilai 30, 60, dan 90 (atau, untuk snapshot mingguan, dua dan tiga koleksi). Buat tabel kecil berisi jumlah baris hasil untuk tiap nilai, lalu pilih satu dan tulis alasannya.
5. **Interval.** Jalankan `deteksi_beacon()` bagian 2.5 atas log koneksi lab, lalu buat grafik sebaran `cv` terhadap `conns`. Pilih ambang dari grafik, bukan dari angka di catatan ini. Sisipkan deret sintetis dengan jitter 20%, 35%, dan 50%, dan catat CV masing-masing serta mana yang lolos.
6. **Join dan validasi.** Lakukan join lintas sumber bagian 2.6 dengan dua dataset yang format nama akun atau nama host-nya sengaja kamu buat berbeda. Perbaiki di sel normalisasi, lalu catat berapa baris tanpa pasangan sebelum dan sesudah perbaikan. Tambahkan satu kunci ganda di tabel kanan dan pastikan `validate="many_to_one"` menghentikan join.
7. **Zona waktu.** Ekspor 1 jam data dari Splunk lab dua kali: sekali dengan `strftime(_time, "%Y-%m-%d %H:%M:%S")`, sekali dengan `eval epoch=_time`. Urai yang pertama dengan `utc=True` dan ukur pergeserannya terhadap yang kedua; lalu pastikan `normalisasi()` bagian 2.2 menolak versi pertama.
8. **MSTICPy.** Pasang MSTICPy versi terkunci, jalankan `init_notebook()`, lalu pakai `IoCExtract` atas data teks bebas. Bandingkan hasilnya dengan regex yang kamu tulis sendiri di Day 05. Bila mencoba TILookup, pakai hanya indikator dari dataset publik.
9. **Higiene.** Pasang `nbstripout --install` di repo latihan, commit notebook yang masih berisi output, lalu periksa versi yang ter-commit (`git show HEAD:<file>`) dan working copy-nya. Bersihkan seluruh output dengan `jupyter nbconvert --clear-output`, lalu buka file `.ipynb` dengan editor teks dan pastikan tidak ada nilai data yang tersisa. Ini langkah yang paling sering dilewati.
10. **Manifest dan retensi.** Tulis manifest untuk file ekspor lab (SHA-256, jumlah baris, query, waktu ekspor), cocokkan jumlah barisnya dengan `resultCount` di Job Inspector, dan tulis aturan retensi lab-mu sendiri dalam satu paragraf beserta alasannya.
11. **Ke SIEM.** Ambil satu analisis dari notebook yang hasilnya stabil, ubah menjadi query terjadwal di SIEM mengikuti Day 14, dan catat alasan pemindahannya di laporan hunt (Day 15).

**Hasil yang sebaiknya tersimpan:**

- Templat notebook hunt dengan sel parameter bertag, sel versi, dan sel normalisasi yang menolak waktu tanpa zona.
- Dua output papermill dengan parameter berbeda, plus catatan jebakan nilai turunan.
- Perbandingan stacking di notebook dan di SIEM, termasuk waktu dan kenyamanan iterasi.
- Tabel jumlah hasil first-seen untuk tiga nilai baseline, beserta pilihan akhir dan alasannya.
- Grafik sebaran CV beserta ambang yang kamu pilih darinya, dan tabel CV deret sintetis untuk tiga tingkat jitter.
- Catatan jumlah baris tanpa pasangan sebelum dan sesudah normalisasi, dan bukti `MergeError` dari kunci ganda.
- Ukuran pergeseran waktu dari ekspor tanpa offset.
- Bukti notebook bersih dari output data sebelum disimpan, dan catatan perbedaan working copy dengan versi yang ter-commit.
- Manifest ekspor lab dan paragraf aturan retensi.
- Satu analisis yang dipindahkan ke query terjadwal, dengan alasannya.

## 4. Troubleshooting

Tabel ini memuat masalah yang sering muncul saat hunt dikerjakan di notebook. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Perbandingan waktu memberi hasil aneh | Zona waktu berbeda antar sumber, atau kolom masih string | Pastikan semua sumber diurai ke UTC; tolak teks tanpa zona (bagian 2.2) |
| Selisih dua sumber hampir persis 7 jam | Teks WIB tanpa offset diurai dengan `utc=True` | Ekspor `epoch`; cek dengan search kecil yang mencetak `%z` (bagian 2.6) |
| Tanggal per hari bergeser satu | `.dt.date` diambil dari UTC | `tz_convert("Asia/Jakarta")` sebelum `.dt.date` |
| Jumlah baris menyusut tanpa penjelasan | Baris dengan timestamp rusak dibuang diam-diam | Cetak jumlah `NaT` sebelum `dropna` (bagian 2.2) |
| Join menghasilkan jauh lebih banyak baris dari semula | Kunci join tidak unik di salah satu sisi | `validate="many_to_one"`; `drop_duplicates()` pada sisi kanan sebelum merge; periksa kardinalitasnya |
| `MergeError` saat merge | Kunci di sisi yang semestinya unik ternyata ganda | Cari kuncinya dengan `duplicated(keep=False)`; perbaiki di sumber, jangan matikan validasi |
| Stacking menunjukkan entri "tersebar" padahal hanya di satu host | Menghitung baris dari koleksi berulang, bukan host | `drop_duplicates` per host lalu `nunique` (bagian 2.4) |
| Satu entitas muncul beberapa kali dengan ejaan berbeda | Normalisasi huruf besar kecil, spasi, atau FQDN terlewat | Terapkan normalisasi identitas di satu tempat saja (`host_pendek()`) |
| Notebook kehabisan memori | Seluruh data dimuat sekaligus | Muat kolom yang diperlukan saja; pakai `chunksize` atau filter saat memuat; persempit di SIEM |
| `exec_query` berhenti dengan error timeout | Bawaan driver Splunk 60 detik | `timeout=` yang lebih besar di `exec_query` [S7] |
| Token ditolak | Header salah, token kedaluwarsa, atau dipakai di instance lain | Header `Authorization: Bearer`; token hanya berlaku di instance penerbit [S23] |
| Login memakai akun lain, bukan token | `username` dan `bearer_token` sama-sama ada di konfigurasi | Hapus `username` dari konfigurasi; autentikasi user lebih diutamakan [S6] |
| Jumlah baris lebih kecil dari `resultCount` | Hasil terpotong batas halaman atau ekspor terputus | Bandingkan dengan Job Inspector; ulangi dengan job biasa |
| `init_notebook()` gagal | `msticpyconfig.yaml` tidak ditemukan atau formatnya salah | Periksa lokasi file dan variabel lingkungan konfigurasinya [S1] |
| Fungsi MSTICPy tidak dikenali setelah upgrade | Nama atau lokasi modul berubah antar versi mayor | Kunci versi di sel versi; cek catatan rilis [S2] |
| Pemasangan MSTICPy menurunkan atau menolak pandas | Requirements MSTICPy membatasi pandas di bawah 3.0 [S14] | Pakai pandas 2.3.3 di environment MSTICPy; environment terpisah bila butuh pandas 3 |
| Hasil berbeda saat dijalankan ulang | Sel dijalankan tidak berurutan sehingga keadaan tercampur | Restart kernel dan jalankan ulang dari awal sebelum menyimpulkan apa pun |
| papermill tidak mengubah nilai turunan | Turunan dihitung di sel parameter | Pindahkan turunan ke sel setelah sel parameter [S28] |

## 5. Kesalahan umum dan jebakan

- Menyimpan notebook beserta output yang memuat data kerja, lalu membagikannya.
- Menganggap nbstripout membersihkan file di VM. Filter hanya membersihkan versi yang di-commit; working copy tetap berisi output [S26].
- Menanam kunci API atau token di dalam sel alih-alih di konfigurasi atau variabel lingkungan.
- Menyebar angka ambang di banyak sel sehingga tidak ada yang tahu nilai mana yang berlaku.
- Menjalankan sel tidak berurutan, lalu menyimpulkan dari keadaan memori yang tidak bisa diulang.
- Melewatkan sel normalisasi, lalu membandingkan identitas yang sebenarnya sama.
- Menganggap `utc=True` sebagai pengaman zona waktu, padahal teks tanpa zona dianggap UTC [S15].
- Membuang baris rusak tanpa menghitungnya.
- Join tanpa `validate` dan tanpa mencetak jumlah baris sebelum dan sesudah.
- Mengekspor "semua sekalian" ke VM, termasuk `_raw`, karena terasa praktis.
- Membiarkan data ekspor tanpa tanggal hapus, sehingga salinannya hidup lebih lama dari sumbernya.
- Memakai notebook sebagai pengganti dashboard atau pengganti query terjadwal.
- Memakai notebook untuk hunt yang sebenarnya lebih cepat satu query di SIEM.
- Menjalankan ulang search besar di search head untuk setiap perubahan ambang, alih-alih menarik sekali.
- Mengirim indikator internal ke layanan threat intelligence luar tanpa persetujuan.
- Menyebut kaitan dua sumber di host yang sama sebagai bukti, tanpa konfirmasi pemilik atau nama proses.

## 6. Catatan terkini

Bagian ini menampung detail versi, tanggal rilis, dan perubahan perilaku pustaka yang dipakai. Berguna saat memasang atau memperbarui lingkungan notebook.

- **MSTICPy 3.1.0 (21 September 2026)** adalah rilis terbaru: menambah TI provider ScanMalware, menambah Python 3.14 sambil tetap mendukung 3.10 sampai 3.13, dan tidak lagi mendukung NumPy 1.x [S2]. Seri 3.0.0 (28 April 2026) membuang Python 3.8 dan 3.9, menghapus `msrestazure` serta extra `kql`, dan menambah provider OpenObserve [S2]. Versi lama Day ini menulis Python 3.8 sebagai syarat minimum; itu berlaku untuk seri 2.x dan sudah tidak berlaku untuk 3.x.
- Requirements di repo MSTICPy membatasi pandas di bawah 3.0, sedangkan NumPy dan IPython dibatasi per versi Python [S14]. Cek metadata rilis yang kamu pasang, karena cabang utama bisa berbeda dari rilisnya.
- **pandas 3.0.0 (21 Januari 2026)** membuat Copy-on-Write menjadi perilaku tetap, menghapus `SettingWithCopyWarning`, menjadikan tipe string khusus sebagai bawaan, menyimpulkan resolusi datetime dari input alih-alih selalu nanodetik, dan butuh Python 3.11 ke atas [S16]. Rilis terbarunya 3.0.6 (17 September 2026); seri 2.x berakhir di 2.3.3 (29 September 2025), rilis pertama yang kompatibel dengan Python 3.14 [S17]. Kode di Day ini ditulis supaya berjalan di 2.3 dan 3.0.
- **JupyterLab 4.6.4 (21 September 2026)** adalah rilis stabil terbaru; 4.7 masih pre-release [S25].
- Daftar backend `QueryProvider` mencakup Splunk, Kusto, MSSentinel, MSDefender, Velociraptor, dan `LocalData` [S1]. Dua yang terakhir berguna di lab: Velociraptor menyambung ke Day 09, dan `LocalData` membuat notebook bisa diuji tanpa SIEM hidup.
- Komponen `AnomalousSequence` dan `EventClustering` menawarkan analisis yang tidak ada padanannya di bahasa query SIEM [S1]. Keduanya layak dicoba, tetapi hasilnya tetap perlu dijelaskan secara manual sebelum masuk laporan; klaster tanpa penjelasan bukan temuan.
- Splunk: endpoint search tanpa versi (`/services/search/jobs`) disebut deprecated sejak endpoint `v2` tersedia di 9.0.1 [S24]; dokumentasi Search Manual 10.6 masih memakai contoh tanpa versi [S21]. Dokumentasi API Velociraptor memuat pemberitahuan untuk memperbarui ke 0.77.3 karena beberapa CVE [S29].
- Notebook mudah berubah menjadi tempat penyimpanan data yang tidak dikelola. Tetapkan sejak awal di mana data mentah tinggal dan berapa lama disimpan, dan jangan biarkan jawabannya menjadi "di folder notebook".

## 7. Cheat sheet

```
PILIH     SIEM: data besar, pola tunggal, hunt yang akan dijadwalkan, dilihat banyak orang
          NOTEBOOK: join lintas skema, statistik di luar bahasa query, iterasi banyak parameter,
                    data yang tidak di-onboard
          > 3x query sama dengan parameter beda -> pindah ke notebook
          notebook sama tiap minggu tanpa diubah -> pindah ke query terjadwal
          pola: persempit di SIEM (indexed field, rentang absolut) -> tarik SEKALI -> iterasi lokal

STRUKTUR  judul+hipotesis | PARAMETER (nilai mentah, tag "parameters") | VERSI | muat+MANIFEST
          | NORMALISASI | analisis (cetak jumlah baris tiap langkah) | hasil
          restart kernel + run all sebelum menyimpulkan; papermill untuk menjalankan ulang

PANDAS    value_counts()               stacking, lihat ekor paling jarang
          groupby().agg()              agregasi per entitas (size, nunique, min, max)
          merge(how="left", validate=, indicator=True)   join; yang TIDAK berpasangan menarik
          sort_values() + groupby().diff()               interval; baris pertama tiap grup kosong
          isin() + mask bernama        penyempitan yang bisa dibaca ulang

WAKTU     ekspor epoch: | eval epoch=_time  ->  pd.to_datetime(x, unit="s", utc=True)
          utc=True: tz-aware DIKONVERSI, tz-naive DIANGGAP UTC  -> tolak teks tanpa zona
          tz diketahui: .dt.tz_localize("Asia/Jakarta").dt.tz_convert("UTC")
          tanggal/jam kerja: .dt.tz_convert("Asia/Jakarta") dulu
          selisih ~7 jam antar sumber = zona waktu sampai terbukti lain

DUPLIKAT  hitung host (nunique), bukan baris | drop_duplicates(subset=...) per host
          baris file == resultCount | duplicated(subset=[fw, session_id])

MSTICPY   init_notebook() | QueryProvider("Splunk").connect(host=, bearer_token=)
          exec_query(q, timeout=900, page_size=10000)   (bawaan 60 s, 100 baris)
          QueryProvider("VelociraptorLogs", data_paths=[...])   JSON satu record per baris
          IoCExtract().extract(data=, columns=, ioc_types=)     lokal
          TILookup(providers=[...]).lookup_iocs(data=, ioc_col=, ioc_type_col=)  KELUAR jaringan
          v3.1.0 | Python 3.10-3.14 | pandas < 3.0 | config msticpyconfig.yaml JANGAN masuk repo

DATA      field dan rentang sesuai abstract, tanpa _raw | disk terenkripsi, akses hunter saja
          mentah dihapus 14 hari setelah laporan disetujui, maks 30 hari setelah ekspor
          token di env var, hak = akun pemilik, hanya di instance penerbit

REPO      notebook tanpa output + queries + manifest + kandidat.csv + report.md
          nbstripout: bersihkan versi commit, working copy TETAP berisi output
          jupyter nbconvert --clear-output <nb>   (menimpa file)
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Semua kolom waktu di notebook sudah diurai dengan `pd.to_datetime(..., utc=True)`, jadi perbandingan waktu antar sumber pasti benar." Benarkah?

<details><summary>Jawaban</summary>

Tidak. `utc=True` mengonversi input yang sudah punya zona ke UTC, tetapi input tanpa zona dianggap sudah UTC. Teks WIB tanpa offset, misalnya hasil `strftime()` di SPL tanpa `%z`, diam-diam bergeser tujuh jam tanpa error, seperti ekspor versi pertama `HUNT-2027-032` yang membuat sesi 09:14 WIB tercatat 16:14. Pengamannya adalah mengekspor epoch dan membuat normalisasi menolak teks waktu tanpa zona. Lihat bagian 1.6 dan 2.6.

</details>

**2. Skenario keputusan.** Notebook beacon firewall POP sudah dijalankan empat Kamis berturut-turut dengan parameter yang sama dan hasilnya selalu ditinjau dengan cara yang sama. Reza bertanya apakah nb01 bisa menjalankannya otomatis tiap Kamis pagi. Langkah mana yang paling tepat?

- A. Jadwalkan notebook dengan cron di nb01 supaya Splunk tidak terbebani.
- B. Tulis tahap A dan B dalam SPL sebagai scheduled search mingguan di luar jam puncak dengan `schedule_window`, serahkan ke Sari sebagai laporan, dan biarkan notebook untuk bagian yang butuh join dengan hasil Velociraptor.
- C. Biarkan tetap dijalankan manual di notebook setiap Kamis, karena notebook lebih fleksibel.

<details><summary>Jawaban</summary>

B. Analisis yang stabil, diulang tiap minggu tanpa diubah, dan bisa ditulis di SPL adalah tanda untuk pindah ke query terjadwal; scheduled search terlihat oleh pemilik konten, punya jadwal yang bisa diatur admin, dan tidak bergantung pada satu VM. A keliru karena notebook terjadwal menambah infrastruktur tanpa menambah nilai, dan tetap menarik data dari Splunk. C keliru karena menjalankan ulang hal yang sama secara manual tanpa pertanyaan baru bukan hunting, dan menghabiskan hari hunting. Lihat bagian 1.1 dan 1.7.

</details>

**3. Pertanyaan jebakan.** "Repo `jab-hunt` sudah memakai nbstripout, jadi file notebook di `jkt-hunt-nb01` bersih dari data dan tidak perlu ikut aturan retensi." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Dalam mode filter, nbstripout hanya membersihkan versi yang di-commit; working copy tetap utuh, termasuk output sel yang memuat nama host, IP, dan akun. File notebook di VM karena itu tunduk pada aturan yang sama dengan data mentah di `raw/`, dan pemeriksaan terakhir sebelum push tetap membuka file `.ipynb` di editor teks. Lihat bagian 1.5 dan 1.7.

</details>

**4. Skenario keputusan.** Saat menyusun hunt berikutnya di nb01, kamu ingin memeriksa reputasi 40 IP tujuan dari daftar kandidat, termasuk beberapa IP internal dan nama host workstation yang ikut terekstrak. Langkah mana yang paling tepat?

- A. Konfigurasi VirusTotal dan OTX di `msticpyconfig.yaml` nb01 dan jalankan `TILookup()` atas seluruh hasil `IoCExtract`.
- B. Pisahkan indikator eksternal dari internal, lalu cek indikator eksternal lewat threat intelligence ES dengan pencarian IOC biasa; bila provider luar memang diperlukan, minta persetujuan dan kirim hanya indikator eksternal dari mesin yang ditetapkan untuk itu.
- C. Jalankan pivot `IpAddress.util.whois` atas semua IP, karena whois bukan layanan threat intelligence.

<details><summary>Jawaban</summary>

B. Mengirim indikator internal, nama host, atau akun ke layanan luar bisa membocorkan informasi tentang organisasi dan memberi tahu penyerang bahwa ia sedang diselidiki; karena itu nb01 sengaja tanpa internet dan tanpa TI provider, dan pengecekan dilakukan lewat threat intelligence ES. A keliru karena tanpa argumen `TILookup()` memuat semua provider yang dikonfigurasi dan mengirim semua indikator, termasuk yang internal, dan nb01 memang tidak punya akses internet. C keliru karena whois juga menghubungi layanan luar, dan IP internal tidak punya arti di whois publik. Lihat bagian 1.4 dan 2.7.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Agus Setiawan (DPO), dalam tiga kalimat, di mana data ekspor `HUNT-2027-032` disimpan, siapa yang bisa membukanya, dan kapan dihapus.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Yang diekspor hanya field yang dibutuhkan hunt ini, yaitu waktu, IP, port, dan ukuran sesi firewall POP selama 28 hari serta daftar task dan autostart dari Velociraptor, tanpa isi log mentah, dan semuanya disimpan di disk terenkripsi VM `jkt-hunt-nb01` yang tidak join domain dan tidak punya akses internet. Yang bisa membukanya hanya akun lokal dua hunter, lewat SSH dari subnet SOC. Data mentah dihapus 14 hari setelah laporan disetujui Dimas atau paling lambat 30 hari setelah diekspor, untuk hunt ini paling lambat 23 April; yang tersisa di repo hanya laporan, query, daftar file dengan hash, dan ringkasan 13 kandidat."

Kesalahan yang sering muncul:
- Hanya menyebut enkripsi disk, padahal DPO juga perlu tahu apa yang diekspor, siapa yang bisa membuka, dan kapan dihapus.
- Lupa menyebut pengecualian: bila hunt menemukan sesuatu, ekspor yang relevan diserahkan ke IR sebagai bukti dengan aturan IR.
- Menyebut retensi tanpa alasan, sehingga terdengar seperti angka sembarang; alasannya adalah salinan tidak boleh hidup lebih lama dari sumbernya.

</details>

**6. Pertanyaan jebakan.** "Left join tidak pernah mengubah jumlah baris tabel kiri, jadi setelah memetakan 612.447 sesi firewall ke host dengan `merge(how="left")`, hasilnya pasti tetap 612.447 baris." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Left join mempertahankan semua baris kiri, tetapi bila kunci di sisi kanan tidak unik, satu baris kiri menjadi beberapa baris. Di `HUNT-2027-032`, IP `10.50.12.19` tercatat dua kali di daftar reservasi DHCP, sehingga setiap sesi dari IP itu akan tergandakan dan diberi dua nama host. `validate="many_to_one"` menghentikan join dengan `MergeError`, dan jumlah baris sebelum dan sesudah join selalu dicetak. Lihat bagian 1.6 dan 2.5.

</details>

**7. Interview question (English).** "When would you take a hunt out of the SIEM and into a Jupyter notebook, and how do you make sure the notebook's results can be trusted?"

<details><summary>Sample answer</summary>

"I move a hunt into a notebook when the question needs things the SIEM does badly: joining sources with different schemas, such as endpoint collection results with firewall sessions and an asset list, statistics the query language doesn't offer, or many threshold iterations over the same data. I still narrow the data in the SIEM with indexed fields and an absolute time range, pull it once as a normal search job so I can record the SID and Job Inspector numbers, and do every iteration locally. To make the result trustworthy, the notebook has one parameter cell, a cell that prints package versions, a manifest with file hashes and row counts that must match the job's result count, and a normalization step that converts everything to UTC and refuses timestamps without a timezone, because a naive local time parsed as UTC shifts everything silently. Every merge uses validation and I print row counts before and after each step. Before any conclusion I restart the kernel and run all cells, and I add a positive control, for example a synthetic beacon series, to prove the analysis can find what I'm looking for. Finally I handle the data like evidence: minimal fields, encrypted storage, a written deletion date, and only the stripped notebook, queries, manifest and a short candidate list go back to the repository."

What makes this answer strong: it frames the notebook as a deliberate trade-off rather than a preference, shows concern for shared SIEM infrastructure, names concrete reproducibility controls (parameters, versions, manifest, validation, positive control), and treats exported data as something with an owner and a lifetime.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | MSTICPy: MSTIC Jupyter and Python Security Tools (dokumentasi resmi) | https://msticpy.readthedocs.io/en/latest/ | primer | dilihat 2026-10-09 | Tinggi. Pemelihara (MSTIC), kelompok komponen dan nama modul, daftar backend `QueryProvider`, `msticpyconfig.yaml`. Syarat Python 3.8 di halaman ini berlaku untuk seri lama; untuk 3.x lihat S2 |
| S2 | Repo microsoft/msticpy (rilis dan aktivitas) | https://github.com/microsoft/msticpy | primer | dilihat 2026-10-09; halaman releases dicek ulang 2026-10-18 | Tinggi. Rilis v3.1.0 bertanggal 2026-09-21 (ScanMalware, Python 3.10-3.14, NumPy 1.x tidak didukung), v3.0.0 2026-04-28 (Python 3.8/3.9 dibuang, OpenObserve), repo tidak diarsipkan |
| S3 | pandas: dokumentasi resmi | https://pandas.pydata.org/docs/ | primer | dirujuk 2026-10-09 | Tinggi untuk perilaku `groupby`, `merge`, `to_datetime`, dan `diff` |
| S4 | Project Jupyter | https://jupyter.org/ | primer | dirujuk 2026-10-09 | Tinggi untuk konsep notebook dan kernel |
| S5 | MITRE ATT&CK: T1059 Command and Scripting Interpreter, T1071 Application Layer Protocol | https://attack.mitre.org/techniques/T1059/ | primer | dirujuk 2026-10-09 | Tinggi untuk ID teknik |
| S6 | MSTICPy: Splunk Provider | https://msticpy.readthedocs.io/en/latest/data_acquisition/SplunkProvider.html | primer | diakses 2026-10-18 | Tinggi. Extra `msticpy[splunk]`, parameter `connect()` (host, port 8089, username/password, bearer_token, verify), prioritas autentikasi user, contoh `exec_query` |
| S7 | MSTICPy: splunk_driver.py (kode sumber, cabang utama) | https://github.com/microsoft/msticpy/blob/main/msticpy/data/drivers/splunk_driver.py | primer | diakses 2026-10-18 | Tinggi untuk perilaku saat ini: job biasa (bukan export), `timeout` 60, `page_size` 100, `count` 0, tanpa konversi `_time`. Cabang utama bisa berbeda dari rilis terpasang |
| S8 | MSTICPy: query_provider_connections_mixin.py (kode sumber) | https://github.com/microsoft/msticpy/blob/main/msticpy/data/core/query_provider_connections_mixin.py | primer | diakses 2026-10-18 | Tinggi. `exec_query()` meneruskan argumen tambahan ke `query()` driver |
| S9 | MSTICPy: Threat Intel Lookups (TIProviders) | https://msticpy.readthedocs.io/en/latest/data_acquisition/TIProviders.html | primer | diakses 2026-10-18 | Tinggi. `TILookup(providers=...)`, provider bawaan, konfigurasi `TIProviders`, anjuran kunci di env atau key vault |
| S10 | MSTICPy: tilookup.py (kode sumber) | https://github.com/microsoft/msticpy/blob/main/msticpy/context/tilookup.py | primer | diakses 2026-10-18 | Tinggi. Parameter `lookup_iocs(data, ioc_col, ioc_type_col, ...)`; tidak ada `obs_col` |
| S11 | MSTICPy: IoC Extraction | https://msticpy.readthedocs.io/en/latest/data_analysis/IoCExtract.html | primer | diakses 2026-10-18 | Tinggi. Tipe IoC, kolom keluaran `IoCType`, `Observable`, `SourceIndex`, path dikecualikan secara bawaan untuk DataFrame |
| S12 | MSTICPy: Pivot Functions | https://msticpy.readthedocs.io/en/latest/data_analysis/PivotFunctions.html | primer | diakses 2026-10-18 | Tinggi. Pivot disiapkan oleh `init_notebook()`, `IpAddress.util.whois(data=, column=)`, `join="left"` |
| S13 | MSTICPy: Velociraptor provider | https://msticpy.readthedocs.io/en/latest/data_acquisition/DataProv-Velociraptor.html | primer | diakses 2026-10-18 | Tinggi. `VelociraptorLogs`, `data_paths`, JSON satu record per baris, query tanpa filter. Contoh jalur akses tabel tidak seragam |
| S14 | MSTICPy: requirements.txt (cabang utama) | https://github.com/microsoft/msticpy/blob/main/requirements.txt | primer | diakses 2026-10-18 | Tinggi untuk batas `pandas>=1.4.0, <3.0.0` dan batas NumPy/IPython per versi Python di cabang utama |
| S15 | pandas: pandas.to_datetime (dokumentasi 3.0.6) | https://pandas.pydata.org/docs/reference/api/pandas.to_datetime.html | primer | diakses 2026-10-18 | Tinggi. `utc=True`: tz-aware dikonversi, tz-naive dilokalisasi sebagai UTC; `errors="coerce"`; `unit` |
| S16 | pandas: What's new in 3.0.0 | https://pandas.pydata.org/docs/whatsnew/v3.0.0.html | primer | 2026-01-21; diakses 2026-10-18 | Tinggi. Copy-on-Write, tipe string bawaan, inferensi resolusi datetime, `as_unit()`, Python 3.11+ |
| S17 | pandas: Release notes (indeks) dan What's new in 2.3.3 | https://pandas.pydata.org/docs/whatsnew/index.html | primer | diakses 2026-10-18 | Tinggi. 3.0.6 (2026-09-17) dan 2.3.3 (2025-09-29, kompatibel Python 3.14) |
| S18 | pandas: DataFrame.merge | https://pandas.pydata.org/docs/reference/api/pandas.DataFrame.merge.html | primer | diakses 2026-10-18 | Tinggi. Opsi `validate`, `indicator` dan nilai `_merge`, perilaku `how="left"` |
| S19 | pandas: DataFrameGroupBy.diff | https://pandas.pydata.org/docs/reference/api/pandas.api.typing.DataFrameGroupBy.diff.html | primer | diakses 2026-10-18 | Tinggi. Selisih di dalam grup, baris pertama tiap grup kosong |
| S20 | pandas: DataFrame.drop_duplicates | https://pandas.pydata.org/docs/reference/api/pandas.DataFrame.drop_duplicates.html | primer | diakses 2026-10-18 | Tinggi. `subset`, `keep`, `ignore_index` |
| S21 | Splunk Enterprise 10.6 Search Manual: Export data using the Splunk REST API | https://help.splunk.com/en/splunk-enterprise/search/search-manual/10.6/export-search-results/export-data-using-the-splunk-rest-api | primer | halaman diperbarui 2025-06-27; diakses 2026-10-18 | Tinggi. Alur job, SID, endpoint results, nilai `output_mode`. Contoh memakai endpoint tanpa versi |
| S22 | Splunk REST API Tutorials 10.2: Creating searches using the REST API | https://help-preview.splunk.com/en/splunk-enterprise/leverage-rest-apis/rest-api-tutorials/10.2/rest-api-tutorials/creating-searches-using-the-rest-api | primer | diakses 2026-10-18 | Tinggi. Export mengalirkan hasil tanpa SID untuk akses kemudian; REST bawaan all time; `earliest_time`/`latest_time` |
| S23 | Splunk Enterprise 10.4: Use authentication tokens | https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/10.4/authenticate-into-the-splunk-platform-with-tokens/use-authentication-tokens | primer | diakses 2026-10-18 | Tinggi. Header Bearer/Splunk, token hanya REST/CLI, hanya di instance penerbit, hak sama dengan akun |
| S24 | Tekstream: Running Searches Using Splunk's REST API, Part One (Jon Walthour) | https://www.tekstream.com/blog/splunk-rest-api-part1/ | sekunder (blog partner) | tanggal terbit tidak tercantum; diakses 2026-10-18 | Sedang. Endpoint `search/v2/jobs` dan `/jobs/export`, endpoint tanpa versi deprecated; cocokkan dengan REST API Reference resmi |
| S25 | JupyterLab releases (GitHub) | https://github.com/jupyterlab/jupyterlab/releases | primer | diakses 2026-10-18 | Tinggi. 4.6.4 stabil terbaru (2026-09-21), 4.7.0a2 pre-release |
| S26 | nbstripout (README) | https://github.com/kynan/nbstripout | primer | diakses 2026-10-18 | Tinggi. Yang dibuang, `--install`, filter wajib, working copy tetap utuh dalam mode filter |
| S27 | nbconvert: Configuration options | https://nbconvert.readthedocs.io/en/latest/config_options.html | primer | diakses 2026-10-18 | Tinggi. Flag `--clear-output` (menyimpan di tempat) dan `--inplace` |
| S28 | papermill: Parameterize | https://papermill.readthedocs.io/en/latest/usage-parameterize.html | primer | diakses 2026-10-18 | Tinggi. Tag `parameters`, sel `injected-parameters`, contoh nilai turunan yang tidak dihitung ulang |
| S29 | Velociraptor: Server API | https://docs.velociraptor.app/docs/server_automation/server_api/ | primer | diakses 2026-10-18 | Tinggi. gRPC `Query`, `config api_client`, role `api`, sertifikat satu tahun, `pyvelociraptor`, anjuran `--env`, pemberitahuan 0.77.3 |
| S30 | Velociraptor VQL reference: hunt_results | https://docs.velociraptor.app/vql_reference/server/hunt_results/ | primer | diakses 2026-10-18 | Tinggi. Argumen `hunt_id`, `artifact`, `source`; butuh `READ_RESULTS` |
| S31 | Velociraptor VQL reference: client_info | https://docs.velociraptor.app/vql_reference/server/client_info/ | primer | diakses 2026-10-18 | Tinggi. `client_info(client_id=...)`, contoh `os_info.hostname` |
| S32 | MITRE ATT&CK v20: T1053.005 Scheduled Task, T1547.001 Registry Run Keys / Startup Folder, T1071.001 Web Protocols | https://attack.mitre.org/techniques/T1053/005/ | primer | diakses 2026-10-18 | Tinggi. T1053.005 v1.8 (Execution, Persistence, Privilege Escalation), T1547.001 v2.1, T1071.001 v1.5 |

**Catatan sumber:** perilaku driver Splunk MSTICPy (job biasa, `timeout`, `page_size`) dan nama argumen `lookup_iocs` diambil dari kode sumber di cabang utama [S7][S8][S10], yang bisa berbeda sedikit dari rilis 3.1.0 yang terpasang; cocokkan dengan versi-mu. Batas pandas di bawah 3.0 berasal dari file requirements cabang utama [S14], bukan metadata rilis di PyPI. Jalur endpoint `search/v2/jobs/export` dan status deprecated endpoint tanpa versi berasal dari sumber sekunder [S24], karena halaman REST API Reference resmi tidak bisa dibuka saat dicek; dokumentasi Splunk yang dibuka masih memakai contoh tanpa versi [S21][S22]. Bentuk keluaran CLI `pyvelociraptor`, nama role baca di Velociraptor yang memberi `READ_RESULTS`, dan jalur impor entitas MSTICPy perlu dicek di versi lab. Seluruh kode pandas di sini ditulis untuk dijalankan di lab dan belum dieksekusi, sehingga nama kolom mengikuti dataset fiktif dan harus disesuaikan. Seluruh isi `HUNT-2027-032` (host, IP, angka, SID, label, orang) adalah penerapan catatan ini pada organisasi fiktif, bukan hasil eksekusi nyata.
