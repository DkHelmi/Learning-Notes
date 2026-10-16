---
day: 02
title: 'Setup lab DFIR: workstation analisis, lab terisolasi, inventaris versi alat, dan bukti read-only'
researched_on: 2026-10-16
versions_checked: 'Volatility 3 2.28.2 (17 Sep 2026, rilis terbaru; Python 3.8 ke atas; symbol pack windows.zip v0.0.1); EZ Tools 2026.5.0 (MFTECmd, EvtxECmd, RECmd, Timeline Explorer; build .NET 9 default, GUI hanya .NET 9); KAPE (Kroll, nomor versi tidak tercantum di halaman EZ Tools; EULA KAPE Solo terakhir diubah 2020-06-04); Velociraptor 0.77.3 (5 Okt 2026, rilis bugfix CVE); Plaso 20260720 (rilis stabil; 20260928 masih pre-release); Sysmon (halaman Microsoft Learn terbit 2026-09-10; Windows 11 dan Server 2019 ke atas); Sysmon bawaan Windows 11 (Insider build 26220.7752 dan 26300.7733, Feb 2026); Get-FileHash (PowerShell 7.6); Mount-DiskImage (Windows Server 2025 docs)'
---

# Day 02: Setup lab DFIR (workstation analisis, lab terisolasi, inventaris versi alat, dan bukti read-only)

Cakupan: menyiapkan dan merawat tempat kerja forensik endpoint, yaitu workstation analisis Windows dan Linux, lab terisolasi untuk menguji alat, rangkaian alat inti beserta versi dan lisensinya, cara membuka bukti tanpa menulis ke master, dan struktur folder kasus.

## Ide inti

Hasil forensik hanya bisa dipertanggungjawabkan bila tempat kerjanya bisa dijelaskan. Saat retainer, DPO, atau auditor bertanya "kenapa CSV-mu berbeda dengan punya kami?", jawabannya hampir selalu ada di tiga hal yang disiapkan sebelum bukti disentuh: alat dan versi persis yang dipakai (parser berubah antar versi, plugin Volatility berganti nama), bukti dibuka dengan cara yang tidak bisa menulis ke master (share read-only, mount read-only, hash sebelum dan sesudah), dan alat sudah diuji pada data yang kamu kenal di lab terisolasi sebelum dipakai pada data yang belum kamu kenal. Setup lab bukan pekerjaan sekali pasang; ia dirawat seperti perangkat produksi: inventaris, jendela update, uji, lalu dibekukan selama kasus berjalan.

Pola ini sudah kamu kenal dari NOC. Sebelum IOS baru dipasang di router agregasi, engineer mengujinya dulu di lab staging yang tidak tersambung ke jaringan pelanggan, mencatat versi lama dan versi baru di inventaris firmware, menyimpan image lama untuk rollback, dan memasangnya hanya di maintenance window. Saat troubleshooting, ia login dengan privilege read-only supaya tidak ada perubahan yang tidak sengaja. Selama gangguan besar berjalan, berlaku change freeze: tidak ada yang meng-upgrade apa pun sampai RFO selesai, karena perubahan di tengah gangguan membuat penyebabnya kabur. Forensik memakai disiplin yang sama, dengan satu tambahan: yang dijaga bukan hanya layanan, tetapi kemampuan membuktikan bahwa bukti tidak berubah.

```
                 JARINGAN MANAJEMEN (tidak join domain, akses tercatat)
  +-------------------------------------------------------------------+
  |  jkt-evid01                                                        |
  |    /evidence/INC-2026-NNN/   master + .sha256   (share read-only)  |
  |    /cases/INC-2026-NNN/      salinan kerja, hasil, catatan (rw)    |
  |         |                         |                                |
  |   JKT-DFIR01 (Win 11)       jkt-dfir02 (Ubuntu LTS)                |
  |   KAPE, EZ Tools,           Volatility 3, Plaso                    |
  |   Timeline Explorer                                                |
  |         |  update alat hanya lewat proxy, per jendela terjadwal    |
  +-------------------------------------------------------------------+
                (tidak ada rute)
  +-------------------------------------------------------------------+
  |  LAB TERISOLASI  host-only 172.16.50.0/24  (bukan produksi)        |
  |    LAB-WS01 (korban, Win 11 + Sysmon, snapshot)  LAB-DFIR01        |
  |    alat baru diuji di sini dulu, pada data yang hasilnya diketahui |
  +-------------------------------------------------------------------+

  urutan: inventaris versi -> update di jendela -> uji di lab -> catat -> bekukan selama kasus
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan. Kasusnya `INC-2026-019`: lampiran phishing `Tagihan-Okt-2026.zip` dijalankan di tiga laptop staf penagihan (`JKT-WS-0388`, `BDG-WS-0142`, `JKT-WS-0412`), lalu kredensial akun service `svc_billing` dipakai untuk masuk ke server billing Linux `jkt-billing01`. Bukti volatil sudah diambil Selasa 2026-10-13, termasuk koleksi triage `JKT-WS-0412` (`INC-2026-019-E14`), dan tersimpan di server bukti `jkt-evid01`. Containment berhasil Rabu 17:20. Kamis 2026-10-15 pukul 09:00, image disk `JKT-WS-0388` (E15) dan `JKT-WS-0412` (E16) dimulai. Pukul 06:30, Yoga Pratama, analyst L2 yang memegang bukti, menulis kepadamu di kanal `#inc-2026-019`:

> "Pagi. Hari ini E14 harus diolah di `JKT-DFIR01`, dan E15 serta E16 masuk siang nanti. Tolong pastikan `JKT-DFIR01` dan `jkt-dfir02` siap sebelum jam 09:00. Terakhir dipakai Agustus untuk latihan, jadi aku tidak yakin isinya. Pertanyaanku: mesin mana mengerjakan apa, dan apa jaminannya tidak tersambung ke mana-mana? Alat apa saja yang harus ada, versi berapa, dan Pak Dimas tanya, KAPE kita itu gratis kan? Jendela proxy update kubuka 07:00 sampai 07:30; perlu update atau tidak, dan bagaimana kalau update malah mengubah hasil? Bagaimana kita tahu alatnya benar sebelum dipakai ke E14? Bukti di `jkt-evid01` di-mount bagaimana supaya tidak ada yang tertulis ke master? Terakhir, folder kasus untuk hasil olahan belum ada strukturnya, dan retainer mau bisa mencocokkan hasil kita dengan punya mereka."

Pesan itu memuat enam pertanyaan:

1. Mesin mana mengerjakan apa, dan bagaimana dipisahkan dari jaringan lain?
2. Alat apa yang harus ada, versi berapa, dan bagaimana status lisensinya?
3. Perlu update pagi ini atau tidak, dan bagaimana mencegah update mengubah hasil kasus?
4. Bagaimana membuktikan alat bekerja benar sebelum menyentuh bukti?
5. Bagaimana bukti dibuka tanpa bisa menulis ke master?
6. Struktur folder kasus dan catatan seperti apa yang membuat hasil bisa dicocokkan pihak lain?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2, pertanyaan 3 di bagian 1.3, pertanyaan 4 di bagian 1.4, pertanyaan 5 di bagian 1.5, dan pertanyaan 6 di bagian 1.6. Bagian 2 berisi perintah dan dokumen yang kamu pakai antara 06:30 dan 08:45 untuk menjawab Yoga.

**Kapan relevan:** saat membangun workstation analisis atau lab DFIR pertama kali, sebelum kasus baru mulai diolah, sebelum dan sesudah update alat, dan setiap kali hasil analisis harus bisa direproduksi atau dicocokkan dengan pihak lain.
**Kapan bukan jawaban:** Day ini tidak mengajarkan cara memakai alat untuk analisis. Koleksi dan pemrosesan KAPE dibahas di Day 03, Velociraptor di Day 04, dan Volatility 3 di Day 14. Day ini juga bukan panduan lab analisis malware: sampel aktif butuh isolasi tersendiri di luar cakupan catatan ini.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day 01 (salinan kerja, hash bukti, case notes, chain of custody, triage collection) tidak diulang. Kolom padanan memakai analogi NOC dan SOC yang dipakai di semua Day Endpoint-Forensics.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Workstation analisis forensik | Mesin khusus untuk mengolah bukti, terpisah dari domain dan internet, dengan alat yang terinventaris | Jump host NOC khusus untuk perangkat inti, dengan akses tercatat |
| Lab terisolasi | Jaringan dan VM yang tidak punya rute ke produksi, tempat alat dan skenario diuji | Lab staging untuk menguji IOS baru sebelum dipasang di router produksi |
| VM korban (lab) | VM yang sengaja dipakai untuk menghasilkan artefak dari aktivitas yang kamu ketahui | Router lab yang dipakai mereproduksi bug |
| Snapshot | Keadaan VM yang disimpan dan bisa dikembalikan | Backup konfigurasi sebelum change, siap untuk rollback |
| Jaringan host-only | Jaringan virtual yang hanya menghubungkan VM dengan host hypervisor, tanpa rute ke luar | VLAN lab yang tidak di-trunk ke uplink |
| Inventaris alat | Daftar alat, versi, sumber unduhan, hash, tanggal, dan lisensi per mesin | Inventaris versi firmware per perangkat |
| Pembekuan versi per kasus | Versi alat tidak diubah selama satu kasus diolah, kecuali dengan uji dan catatan | Change freeze selama gangguan besar sampai RFO selesai |
| Target dan Module (KAPE) | Definisi apa yang dikumpulkan (Target) dan program apa yang memproses hasilnya (Module) | Template `show` yang diambil dan skrip yang mem-parse hasilnya |
| Ancillary files | Berkas pendukung parser: maps EvtxECmd, batch file RECmd, definisi Target dan Module | File MIB dan template parsing yang ikut menentukan isi laporan |
| Symbol table (Volatility 3) | Berkas yang menjelaskan struktur data kernel satu build OS, dibutuhkan untuk membaca image memori Windows | File MIB untuk menerjemahkan OID SNMP |
| Read-only mount | Membuka share atau image tanpa izin tulis dari sisi klien | Login dengan privilege read-only di perangkat |
| Uji alat pada data yang diketahui | Menjalankan alat pada artefak yang isinya sudah kamu ketahui untuk memastikan hasilnya benar | Uji konfigurasi baru di lab dengan trafik yang hasilnya sudah diketahui |

### 1.1 Topologi: tiga ruang yang tidak boleh tercampur

Pertanyaan pertama Yoga ("mesin mana mengerjakan apa, dan apa jaminannya tidak tersambung ke mana-mana?") dijawab dengan memisahkan tiga ruang: tempat bukti dihasilkan, tempat bukti dianalisis, dan bukti itu sendiri. Tanpa pemisahan ini, mudah mencemari bukti atau menjalankan sesuatu yang berbahaya di tempat yang salah.

Tabel berikut adalah topologi dasar lab DFIR. Baca kolom Catatan, karena di situlah aturan yang paling sering dilanggar.

| Peran | Isi | Catatan |
|---|---|---|
| VM korban (Windows) | Windows 10/11 dengan Sysmon dan audit policy yang diperluas (bagian 1.4), tempat aktivitas jinak dijalankan | Snapshot bersih sebelum tiap skenario |
| VM analisis | EZ Tools, KAPE, Volatility 3, Timeline Explorer, Registry Explorer; tempat artefak diparse | Tidak menjalankan sampel; hanya menganalisis |
| Server Velociraptor (opsional) | Server + client di VM korban (Day 04) | Untuk koleksi lintas host |

Penyimpanan bukti adalah folder read-only atau share terpisah tempat artefak yang dikumpulkan disimpan dan di-hash (Day 01). Jangan menganalisis di folder yang sama tempat bukti asli disimpan; bekerja di salinan.

Aturan isolasi yang menyertai topologi itu:

- **Jaringan host-only atau internal.** VM korban tidak boleh menjangkau internet atau jaringan nyata saat menjalankan skenario, agar aktivitas uji tidak bocor dan sampel tidak menyebar.
- **Snapshot.** Ambil snapshot bersih VM korban sebelum tiap skenario, kembalikan setelahnya.
- **VM analisis tidak menjalankan sampel.** Ia memparse artefak mati (file, hive, image memori), bukan mengeksekusi biner yang dicurigai.
- **Image memori dan sampel diperlakukan sebagai data.** Volatility 3 menganalisis image sebagai file; tidak menjalankan isinya.

Di PT JAB, ketiga ruang itu ada dalam dua tingkat. Untuk kasus nyata, ruang analisis adalah `JKT-DFIR01` (VM Windows 11) dan `jkt-dfir02` (VM Ubuntu LTS untuk Volatility 3 dan Plaso), keduanya di jaringan manajemen yang sama dengan `jkt-evid01`, tidak join domain `corp.jab.example`, dan tanpa akses internet kecuali lewat proxy terbatas yang hanya dibuka per jendela update terjadwal. Tidak join domain berarti akun domain yang mungkin dikuasai penyerang tidak bisa login ke mesin itu, dan kebijakan grup produksi tidak ikut mendorong perubahan ke sana. Ruang bukti adalah `/evidence/INC-2026-019/` di `jkt-evid01`. Untuk menguji alat dan berlatih, ada lab terisolasi terpisah: VM korban `LAB-WS01` (Windows 11 dengan Sysmon), VM analisis lab `LAB-DFIR01`, dan jaringan host-only `172.16.50.0/24` yang tidak punya rute ke jaringan manajemen maupun produksi. Alat baru masuk ke lab lewat disk virtual atau ISO yang dipasang dari hypervisor, bukan lewat jembatan jaringan, supaya isolasi tidak dibuka hanya untuk menyalin file.

Lab yang sama dipakai sepanjang topik ini: Day 03 sampai 13 memakai artefak disk dan registry dari VM korban, Day 14 sampai 16 memakai image memorinya, dan Day 17 sampai 18 menjalankan simulasi kasus penuh. Membangunnya benar sekarang menghemat waktu nanti.

Jawaban ke Yoga untuk pertanyaan pertama: `JKT-DFIR01` mengolah artefak Windows (E14, lalu E15 dan E16), `jkt-dfir02` menyiapkan Volatility 3 dan Plaso bila retainer mengirim pertanyaan lanjutan tentang memori atau timeline, dan semua alat diuji di lab dulu. Jaminannya bukan janji, tetapi konfigurasi yang bisa diperiksa: aturan firewall jaringan manajemen, status proxy di luar jendela, dan status keanggotaan domain kedua mesin (dicek di bagian 2.1).

### 1.2 Rangkaian alat inti, versi, dan lisensi

Pertanyaan kedua Yoga punya tiga bagian: alat apa, versi berapa, dan apakah KAPE gratis. Tabel berikut adalah rangkaian alat yang menutup disk, registry, event log, memori, dan timeline, cukup untuk seluruh rangkaian Day. Baca kolom Lisensi/catatan dengan teliti, karena di situ jebakan untuk organisasi komersial.

| Alat | Fungsi | Lisensi/catatan |
|---|---|---|
| EZ Tools (Eric Zimmerman) | Parser artefak Windows (MFT, registry, Prefetch, event log, dll.) | Gratis; .NET 9 default; updater Get-ZimmermanTools [S2] |
| KAPE (Kroll) | Koleksi triage (Targets) dan pemrosesan (Modules) | Edisi gratis (Solo) hanya untuk penggunaan non-komersial; penggunaan untuk tujuan bisnis butuh KAPE Enterprise License [S3][S11] |
| Velociraptor | Koleksi dan hunting lintas endpoint (VQL, artifact) | Open source; 0.77.3 [S4] |
| Volatility 3 | Analisis memori | Open source; 2.28.2; Python [S1] |
| Plaso (log2timeline) + Timesketch | Super-timeline dan visualisasinya | Open source (Day 13) [S5] |
| Timeline Explorer, Registry Explorer (EZ) | GUI untuk membaca hasil parse | Bagian EZ Tools, .NET 9 [S2] |

EZ Tools adalah kumpulan parser command-line dan GUI dari Eric Zimmerman [S2]. Tabel berikut memetakan tool yang paling dipakai ke artefak dan Day yang membahasnya; gunakan sebagai daftar minimum yang harus menampilkan versi di `JKT-DFIR01`.

| Tool | Artefak | Day |
|---|---|---|
| MFTECmd | `$MFT`, `$J` (USN), `$LogFile` | 08 |
| RECmd, Registry Explorer | Registry hive | 09 |
| PECmd | Prefetch | 07 |
| AppCompatCacheParser, AmcacheParser | Shimcache, Amcache | 07 |
| EvtxECmd | Windows event log (.evtx ke CSV/JSON) | 05 |
| JLECmd, LECmd | Jump list, LNK | 10 |
| SBECmd, ShellBags Explorer | ShellBags | 10 |
| SrumECmd | SRUM | 07 |
| Timeline Explorer | Membaca CSV hasil parse | semua |

EZ Tools dibangun dalam dua varian: .NET 4.7.2 (label 4) dan .NET 9 (label 9). Semua tool GUI kini hanya tersedia untuk .NET 9, sedangkan tool CLI masih dibangun untuk keduanya. Tool .NET 9 butuh runtime .NET 9 atau yang lebih baru, dan untuk program GUI yang dibutuhkan adalah Desktop runtime, bukan hanya runtime biasa [S2]. Per 2026-10-16, halaman resmi mencantumkan MFTECmd, EvtxECmd, RECmd, dan Timeline Explorer di versi 2026.5.0 [S2].

Soal lisensi KAPE, jawabannya ke Dimas: tidak, untuk PT JAB KAPE tidak gratis. EULA KAPE Solo menyebut edisi itu alat gratis untuk tujuan non-komersial: pemakaian pribadi, lembaga penegak hukum pemerintah, serta pelajar dan institusi pendidikan untuk belajar dan riset. Penggunaan komersial didefinisikan sebagai penggunaan untuk tujuan bisnis, dan siapa pun yang memakai KAPE untuk tujuan komersial membutuhkan KAPE Enterprise License [S11]. FAQ di dokumentasi KAPE yang lebih baru (diperbarui Februari 2026) menulis hal yang tidak sepenuhnya sejalan: KAPE gratis untuk pemerintah, pendidikan, riset, dan penggunaan internal perusahaan, dan sejak 1 Januari 2026 tidak lagi tersedia untuk penggunaan komersial, yaitu di jaringan pihak ketiga atau dalam engagement berbayar [S24]. Karena EULA belum diubah sejak 2020, PT JAB memakai tafsir yang lebih ketat. Ketentuan Enterprise mengizinkan KAPE dipasang dan dijalankan di jaringan pemegang lisensi, dengan jumlah pengguna dibatasi angka yang tertulis di order, dan lisensinya tidak bisa dialihkan tanpa persetujuan tertulis Kroll [S23]. Mengolah bukti insiden perusahaan adalah tujuan bisnis, jadi PT JAB harus memegang lisensi Enterprise, dan inventaris alat mencatat nomor order serta daftar pengguna terdaftarnya. Lab pribadimu di rumah untuk belajar termasuk penggunaan pribadi non-komersial. Bila ragu tentang kasus tertentu, tanyakan langsung ke Kroll sebelum dipakai; ini bukan nasihat hukum.

### 1.3 Update terkendali dan pembekuan versi selama kasus

Pertanyaan ketiga Yoga ("perlu update atau tidak, dan bagaimana kalau update malah mengubah hasil?") adalah pertanyaan change management. Hasil forensik bergantung versi alat: plugin Volatility berganti nama, parser EZ diperbaiki, Target KAPE ditambah. Volatility 3 2.26.2, misalnya, memindahkan sebagian plugin ke subpaket `malware` (contoh: `linux.check_afinfo` menjadi `linux.malware.check_afinfo`); nama lama masih berjalan sampai dihapus [S1]. Velociraptor 0.77.3 mengubah offset tempat `Windows.Forensics.Prefetch` membaca VolumeSerialNumber, dan mengubah kolom yang dikeluarkan artifact backup server [S4]. Dua analyst yang memproses berkas sama dengan versi berbeda bisa mendapat CSV yang berbeda, dan keduanya "benar" untuk versinya masing-masing.

Yang perlu di-update juga bukan hanya biner. Ada tiga lapisan:

1. **Biner alat.** EZ Tools lewat `Get-ZimmermanTools` [S2], Velociraptor dan Volatility dari halaman rilis [S4][S1], Plaso dari rilis atau image Docker [S16][S15].
2. **Definisi dan ancillary files.** Target dan Module KAPE diperbarui dengan `kape.exe --sync` atau tombol Sync with GitHub di gkape [S12]. Maps EvtxECmd, maps SQLECmd, dan batch file RECmd ikut menentukan isi CSV. Skrip komunitas KAPE-EZToolsAncillaryUpdater memperbarui KAPE (lewat `Get-KAPEUpdate.ps1`), EZ Tools di `.\KAPE\Modules\bin`, dan ancillary files tersebut sekaligus [S14].
3. **Data yang diunduh saat alat berjalan.** Volatility 3 mencari symbol table Windows di direktori simbol lokal; bila tidak ada yang cocok, ia mengunduh PDB dari Microsoft Symbol Server, mengonversinya, dan menyimpannya [S10]. Di `jkt-dfir02` yang tidak punya internet, langkah itu gagal diam-diam sampai kamu membaca pesan error-nya.

Lapisan kedua sering terlupa: EZ Tools yang berdiri sendiri di `C:\DFIR\tools\EZTools` dan EZ Tools di `Modules\bin` milik KAPE adalah salinan terpisah, sehingga bisa berbeda versi. Module `!EZParser` di Day 03 menjalankan salinan di `Modules\bin`, bukan yang di folder EZ Tools.

Prinsip yang dipakai PT JAB, dan jawaban ke Yoga:

- Update dilakukan sebelum bukti suatu kasus pertama kali diproses, lalu versi dibekukan sampai kasus selesai. Pagi ini tepat untuk update, karena E14 belum diolah.
- Update di tengah kasus hanya bila ada alasan kuat (bug yang memengaruhi artefak yang sedang dianalisis, atau celah keamanan), diuji di lab, dicatat, dan bukti yang sudah diproses dengan versi lama ditandai atau diproses ulang.
- Versi lama tidak ditimpa; folder alat disimpan per tanggal update supaya hasil lama bisa direproduksi.
- Rilis pre-release tidak dipakai untuk kasus. Halaman rilis Plaso, misalnya, menandai 20260928 sebagai pre-release untuk pengujian, sedangkan rilis stabilnya 20260720 [S16].
- Velociraptor wajib di 0.77.3 sebelum server kasus dibangun (Day 04): rilis itu adalah perbaikan untuk CVE yang terbit di siklus rilisnya, dan dokumentasi proyek meminta pengguna memperbarui ke versi itu [S4][S18].

Pencatatan versi adalah separuh dari jawaban. Hasil forensik bergantung versi alat, jadi catat nama alat, versi, tanggal pasang, dan lisensi di inventaris. Ini memenuhi aturan akurasi (sebut versi) dan mencegah kejutan saat hasil berbeda setelah update. Di PT JAB, inventaris itu disimpan per mesin dan disalin ke folder kasus setiap kali kasus mulai diolah (bagian 2.1 dan 2.8).

### 1.4 Uji alat di lab terisolasi sebelum menyentuh bukti

Pertanyaan keempat Yoga ("bagaimana kita tahu alatnya benar sebelum dipakai ke E14?") dijawab dengan uji pada data yang hasilnya sudah kamu ketahui. Kalau kamu sendiri yang membuat scheduled task bernama `LabTask01` di `LAB-WS01` pukul 07:42, lalu parser yang baru di-update tidak menampilkannya, masalahnya ada di alat atau di caramu memakainya, bukan di bukti. Uji yang sama pada E14 tidak bisa membedakan dua kemungkinan itu, karena isi E14 belum kamu ketahui.

Supaya VM korban menghasilkan artefak yang cukup untuk diuji, telemetrinya diperkaya. Pasang Sysmon dengan konfigurasi komunitas yang umum (misalnya konfigurasi SwiftOnSecurity atau Olaf Hartong) agar ada event proses (EID 1), koneksi jaringan (EID 3), file dibuat (EID 11), dan perubahan registry (EID 12-14). Aktifkan juga audit policy yang tidak menyala secara default: Audit Process Creation beserta setting "Include command line in process creation events" (menghasilkan 4688 dengan command line), Audit User Account Management (4720, 4728, 4732), Audit Other Object Access Events (4698 untuk scheduled task), dan PowerShell Script Block Logging (4104). Tanpa ini, banyak event yang dipakai di Day 05 dan 11 tidak akan muncul di lab [S6][S7].

Tiga detail Sysmon yang mengubah hasil uji [S6]:

- Instalasi tanpa file konfigurasi memakai hash SHA1 untuk image proses dan tidak memantau jaringan. Event koneksi jaringan (EID 3) mati secara bawaan, jadi uji yang mengandalkan EID 3 butuh konfigurasi yang menyalakannya.
- `sysmon -c` tanpa argumen menampilkan konfigurasi yang sedang aktif. Simpan keluarannya bersama snapshot supaya kamu tahu event apa yang memang bisa muncul.
- Timestamp event Sysmon dalam UTC. Bila aktivitas uji dicatat dalam WIB, selisih 7 jam itu harus ada di catatan uji.

Data untuk latihan berasal dari tiga sumber, karena catatan ini tidak memakai data kerja atau data klien:

- **Aktivitas lab sendiri:** jalankan aktivitas jinak di VM korban, lalu kumpulkan artefaknya. Paling fleksibel dan aman. Untuk meniru teknik penyerang secara terkendali, katalog Atomic Red Team (Red Canary) berisi test kecil per teknik ATT&CK, masing-masing dengan ID teknik dan GUID, perintah yang dijalankan, dan perintah cleanup. Pilih test berdasarkan ID teknik, baca isinya untuk memahami jejak yang akan muncul (proses, file, key registry, event), lalu jalankan hanya di VM korban dengan snapshot [S8].
- **Dataset publik DFIR:** image dan koleksi latihan dari sumber seperti CyberDefenders, DFIR Report (artefak yang dipublikasikan), dan tantangan CTF forensik. Cek lisensi tiap dataset sebelum dipakai atau dipublikasikan ulang; banyak yang gratis untuk latihan tetapi tidak untuk redistribusi.
- **Image memori sampel:** sebagian tersedia untuk latihan Volatility (Day 14). Perlakukan sebagai data; jangan jalankan isinya.

Jangan mengunduh sampel malware liar ke lab yang tidak dirancang untuknya; analisis malware aktif berada di luar cakupan catatan ini dan butuh lab dengan isolasi tersendiri.

Di PT JAB pagi itu, uji dilakukan di `LAB-WS01` yang dikembalikan ke snapshot `bersih-2026-10-15`, dengan aktivitas yang kamu tulis jamnya sendiri, lalu artefaknya diproses dengan versi alat yang baru di-update dan dibandingkan dengan hasil versi sebelumnya (bagian 2.3).

### 1.5 Membuka bukti tanpa bisa menulis ke master

Pertanyaan kelima Yoga ("di-mount bagaimana supaya tidak ada yang tertulis ke master?") dijawab dengan tiga lapis kontrol, karena satu lapis saja tidak cukup:

1. **Izin di sisi server.** Share `\\jkt-evid01\evidence` hanya memberi izin baca untuk akun analyst. Yang bisa menulis ke `/evidence/INC-2026-019/` hanya pemegang bukti (Yoga, dengan `adm.yoga`). Ini kontrol terkuat, karena tidak bergantung pada kehati-hatian klien.
2. **Mount read-only di sisi klien.** Di Linux, opsi `ro` membuat filesystem di-mount read-only. Halaman manual `mount` sendiri memperingatkan bahwa, bergantung jenis filesystem, keadaan, dan perilaku kernel, sistem tetap bisa menulis ke device; ext3 dan ext4 akan me-replay journal bila filesystem dalam keadaan dirty. Untuk ext3/ext4, pakai `ro,noload`, atau jadikan block device read-only dengan `blockdev` [S21]. Di Windows, `Mount-DiskImage` me-mount VHD/VHDX dalam mode read-write bila parameter `-Access` tidak dipakai; ISO selalu read-only [S20]. Ini penting karena koleksi KAPE sering berbentuk container VHDX, seperti E14.
3. **Hash sebelum dan sesudah.** Hash membuktikan bahwa master tidak berubah, apa pun yang terjadi di dua lapis pertama (Day 01). Verifikasi `sha256sum -c` sebelum salinan kerja dibuat, dan sekali lagi saat kasus ditutup.

Satu aturan lagi menyatukan ketiganya: yang di-mount untuk dianalisis adalah salinan kerja, bukan master. Master hanya dibaca untuk dua hal, yaitu diverifikasi hash-nya dan disalin. Di `INC-2026-019`, E14 diverifikasi ulang Yoga pukul 08:52, lalu salinan kerja `E14-W1` dibuat di area kerja kasus dan diolah di `JKT-DFIR01` (Day 03).

### 1.6 Struktur folder kasus dan catatan yang bisa dicocokkan pihak lain

Pertanyaan terakhir Yoga menyangkut retainer: mereka akan memproses bukti yang sama dengan alat mereka sendiri, lalu membandingkan. Perbandingan itu hanya bisa dilakukan bila setiap hasil bisa ditelusuri ke tiga hal: bukti mana (nomor bukti dan hash), alat apa (nama dan versi), dan kapan serta oleh siapa.

Prinsip kebersihan bukti dari Day 01 diterapkan secara konkret:

- Hash tiap koleksi artefak saat dibuat (`Get-FileHash` atau `sha256sum`), simpan daftar hash terpisah.
- Bekerja di salinan, bukan bukti asli.
- Catat waktu, sumber, dan metode tiap koleksi (catatan kasus).
- Folder kerja per kasus memisahkan bukti mentah, hasil analisis, dan catatan.

Meski di lab latihan, membiasakan kebersihan bukti sekarang membuatnya refleks saat kasus nyata.

Di PT JAB, pemisahan itu diwujudkan dengan dua pohon folder di `jkt-evid01`: `/evidence/INC-2026-019/` untuk master (read-only bagi analyst) dan `/cases/INC-2026-019/` untuk salinan kerja, hasil olahan, catatan, dan salinan inventaris alat saat kasus diolah. Nama folder hasil memuat nomor bukti dan versi alat, misalnya `analysis/E14-W1/EZ-2026.5.0/`, sehingga retainer langsung tahu versi parser yang menghasilkan CSV itu tanpa harus bertanya. Strukturnya ada di bagian 2.8.

## 2. Contoh dan langkah praktis di PT JAB

Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi. Perintah ditulis untuk lingkungan PT JAB; untuk latihan, jalankan hanya di VM lab terisolasi (bagian 3). Nama perintah dan opsi diambil dari dokumentasi versi yang tercantum di front matter; cek ulang dengan bantuan alat (`-h`, `--help`) di versi-mu.

### 2.1 Inventaris versi dan status mesin (06:35, `JKT-DFIR01`)

Langkah pertama menjawab pertanyaan kedua Yoga sebelum apa pun diubah: apa yang sebenarnya terpasang sekarang. Inventaris lama hanya bertuliskan "EZ Tools terbaru, Agustus", yang tidak bisa dipakai untuk mereproduksi hasil.

**Tujuan:** mencatat versi setiap biner EZ Tools dan KAPE, serta memastikan mesin tidak join domain.

```powershell
Get-ChildItem C:\DFIR\tools -Recurse -Include *.exe |
  Select-Object Name, @{n='FileVersion';e={$_.VersionInfo.FileVersion}}, DirectoryName |
  Sort-Object Name | Format-Table -AutoSize
(Get-CimInstance Win32_ComputerSystem).PartOfDomain
Get-Date -Format o
```

- `Get-ChildItem -Recurse -Include *.exe`: semua executable di folder alat, termasuk salinan EZ Tools di `KAPE\Modules\bin`.
- `VersionInfo.FileVersion`: versi yang tertanam di metadata file. Untuk EZ Tools, cocokkan juga dengan versi yang ditampilkan saat tool dijalankan tanpa argumen.
- `PartOfDomain`: `False` berarti mesin tidak join domain, sesuai desain bagian 1.1.
- `Get-Date -Format o`: waktu inventaris dengan offset zona waktu, untuk catatan.

Keluaran ilustrasi (dipotong):

```
Name             FileVersion  DirectoryName
----             -----------  -------------
EvtxECmd.exe     2026.5.0     C:\DFIR\tools\EZTools\net9\EvtxECmd
EvtxECmd.exe     <lebih lama> C:\DFIR\tools\KAPE\Modules\bin\EvtxECmd
kape.exe         <versi>      C:\DFIR\tools\KAPE
MFTECmd.exe      2026.5.0     C:\DFIR\tools\EZTools\net9
MFTECmd.exe      <lebih lama> C:\DFIR\tools\KAPE\Modules\bin
...
False
2026-10-15T06:35:41.1029384+07:00
```

**Cara membaca hasil:** dua baris `EvtxECmd.exe` dengan versi berbeda adalah temuan, bukan kesalahan ketik: salinan di `Modules\bin` milik KAPE tertinggal dari salinan berdiri sendiri (bagian 1.3). Bila tidak dibereskan, Module `!EZParser` di Day 03 akan memakai versi lama walaupun inventaris EZ Tools menunjukkan 2026.5.0. Format nomor versi persis yang tertanam di metadata EZ Tools perlu dicek di mesin-mu; contoh di atas hanya menunjukkan polanya.

**Variasi:** di `jkt-dfir02`, inventaris dibuat dengan `pip show volatility3` di virtualenv Volatility dan `docker images --digests` untuk image Plaso. Digest image lebih kuat daripada tag `latest`, karena tag bisa menunjuk image lain setelah update.

**Kapan gagal:** alat yang dijalankan dari lokasi lain (misalnya disalin ke desktop "sementara") tidak masuk inventaris. Aturannya: alat untuk kasus hanya dijalankan dari `C:\DFIR\tools`.

### 2.2 Update di jendela proxy (07:00 sampai 07:30)

Langkah ini menjawab pertanyaan ketiga Yoga: update dilakukan sekarang, sebelum E14 diproses, lalu dibekukan.

**Tujuan:** memperbarui biner dan definisi ke folder baru tanpa menimpa versi lama, lalu mencatat hash setiap arsip yang diunduh.

```powershell
# 1. EZ Tools ke folder bertanggal (default .NET 9)
.\Get-ZimmermanTools.ps1 -Dest C:\DFIR\tools\EZTools-2026-10-15 -NetVersion 9

# 2. Definisi Target dan Module KAPE
C:\DFIR\tools\KAPE\kape.exe --sync

# 3. Hash arsip yang diunduh manual (contoh: Velociraptor untuk toolkit)
Get-FileHash -Path .\velociraptor-v0.77.3-windows-amd64.exe -Algorithm SHA256
```

- `-Dest`: lokasi tujuan. Bila tidak diisi, tool ditaruh di folder skrip, dan halaman resmi tidak menyarankannya [S2]. Folder bertanggal menjaga versi lama tetap utuh.
- `-NetVersion 9`: build .NET 9, nilai default; `4` untuk .NET 4.7.2, `0` untuk semua [S2].
- `kape.exe --sync`: memperbarui Target dan Module dari repo KapeFiles [S12]. Biner KAPE sendiri dan EZ Tools di `Modules\bin` tidak ikut diperbarui oleh perintah ini; untuk itu dipakai `Get-KAPEUpdate.ps1` dan pembaruan `Modules\bin` (bagian 1.3) [S13][S14].
- `Get-FileHash`: SHA256 adalah default; bila halaman rilis menerbitkan hash, bandingkan nilai yang kamu hitung dengan nilai yang diterbitkan, seperti contoh di dokumentasi PowerShell [S19]. Bila tidak ada hash terbitan, hash yang kamu hitung tetap dicatat sebagai baseline untuk salinan di toolkit.

Keluaran ilustrasi (ringkas, dari catatan update):

```
07:04  Get-ZimmermanTools: 2026.5.0 untuk semua tool CLI dan GUI; tidak ada versi baru sejak Agustus
07:09  kape.exe --sync: Target dan Module diperbarui (jumlah file berubah dicatat dari keluaran)
07:15  KAPE-EZToolsAncillaryUpdater: Modules\bin EvtxECmd, MFTECmd, RECmd diperbarui; maps EvtxECmd diperbarui
07:21  velociraptor-v0.77.3-windows-amd64.exe  SHA256 7c2e...  (toolkit sebelumnya 0.77.1)
07:26  proxy ditutup (konfirmasi NOC)
```

**Cara membaca hasil:** update tidak selalu mengubah biner. Pagi ini EZ Tools berdiri sendiri sudah di versi terbaru; yang berubah adalah definisi KAPE, salinan di `Modules\bin`, dan maps. Justru perubahan itulah yang paling mungkin menggeser isi CSV, sehingga uji di bagian 2.3 tetap wajib.

**Variasi:** README KAPE-EZToolsAncillaryUpdater menyebut bahwa sejak versi 4.0 skrip hanya mengunduh build .NET 6 EZ Tools [S14], sedangkan halaman EZ Tools kini menawarkan build .NET 4.7.2 dan .NET 9 [S2]. Sebelum memakai skrip itu, cek build mana yang benar-benar diunduhnya di versi skrip-mu, supaya `Modules\bin` tidak berisi build yang runtime-nya tidak terpasang.

**Kapan gagal:** jendela proxy ditutup sebelum unduhan selesai, sehingga sebagian tool baru dan sebagian lama. Inventaris ulang (bagian 2.1) setelah update selalu dijalankan, bukan hanya bila ada error.

### 2.3 Uji regresi di lab (07:35 sampai 08:15, `LAB-WS01` dan `LAB-DFIR01`)

Langkah ini menjawab pertanyaan keempat Yoga: membuktikan alat yang baru di-update menghasilkan apa yang seharusnya, pada data yang kamu kenal.

**Tujuan:** membuat artefak dengan isi yang diketahui, memprosesnya dengan versi lama dan versi baru, lalu membandingkan.

Langkah di lab:

1. Kembalikan `LAB-WS01` ke snapshot `bersih-2026-10-15`. Cek konfigurasi Sysmon aktif dengan `sysmon -c` dan simpan keluarannya.
2. Jalankan aktivitas yang jamnya kamu catat (WIB): buat scheduled task `LabTask01` pukul 07:42, jalankan `notepad.exe` dan `powershell.exe -c Get-Date` pukul 07:44.
3. Ekspor log dengan `wevtutil epl Microsoft-Windows-Sysmon/Operational C:\Temp\sysmon.evtx` dan `wevtutil epl Security C:\Temp\security.evtx`, salin ke `LAB-DFIR01` lewat disk virtual, lalu hash.
4. Proses kedua berkas dengan EvtxECmd versi lama dan versi baru ke dua folder berbeda.

```powershell
C:\DFIR\tools\EZTools-2026-08\EvtxECmd\EvtxECmd.exe -f C:\CASE-2026-LAB-002\evidence\sysmon.evtx --csv C:\CASE-2026-LAB-002\analysis\lama
C:\DFIR\tools\EZTools-2026-10-15\net9\EvtxECmd\EvtxECmd.exe -f C:\CASE-2026-LAB-002\evidence\sysmon.evtx --csv C:\CASE-2026-LAB-002\analysis\baru
```

- `-f`: satu berkas `.evtx` yang diproses.
- `--csv`: folder keluaran CSV. Kedua versi diarahkan ke folder berbeda supaya hasilnya bisa dibandingkan.
- Path folder versi lama (`EZTools-2026-08`) adalah contoh; sesuaikan dengan folder bertanggal di mesin-mu. Cek opsi persis dengan `EvtxECmd.exe` tanpa argumen.

Keluaran ilustrasi (perbandingan yang dicatat):

```
Berkas        Versi lama   Versi baru   Catatan
sysmon.evtx   412 baris    412 baris    jumlah sama; kolom PayloadData lebih terisi di versi baru (maps diperbarui)
security.evtx 1.287 baris  1.287 baris  jumlah sama
Cek isi:      4698 LabTask01 07:42 WIB (00:42 UTC) muncul di kedua versi
              Sysmon EID 1 notepad.exe dan powershell.exe 07:44 WIB (00:44 UTC) muncul di kedua versi
```

**Cara membaca hasil:** jumlah baris yang sama menunjukkan parser membaca event yang sama. Perbedaan di kolom hasil maps adalah perubahan yang diharapkan dari update maps, dan harus dicatat karena retainer yang memakai maps lama akan melihat kolom berbeda. Aktivitas yang kamu buat sendiri muncul dengan jam yang benar setelah dikonversi dari UTC, jadi alat dan cara pakainya terbukti sebelum E14 disentuh.

**Variasi:** uji yang sama untuk MFTECmd pada `$MFT` dari `LAB-WS01`, dan untuk Volatility 3 di `jkt-dfir02` pada image memori lab (Day 14).

**Kapan gagal:** uji hanya membuktikan alat bekerja untuk artefak yang diuji. Artefak yang tidak pernah diuji (misalnya format dari build Windows yang berbeda dengan `LAB-WS01`) tetap harus dibaca dengan hati-hati.

### 2.4 Verifikasi KAPE

KAPE dijalankan dari foldernya (gkape.exe GUI atau kape.exe CLI) [S3]. Langkah ini memastikan KAPE di `JKT-DFIR01` mengenali definisi hasil sync, tanpa mengumpulkan apa pun.

```
kape.exe --tlist
kape.exe --mlist
```

- `--tlist` menampilkan daftar Target (apa yang bisa dikumpulkan); `--mlist` daftar Module (pemrosesan).
- Pada Day 03 kamu menjalankan koleksi dan pemrosesan sebenarnya; hari ini cukup pastikan KAPE mengenali Target dan Module.
- Third-party executable yang dipanggil Module ditaruh di `\KAPE\Modules\bin` [S13]. Module yang binernya tidak ada di sana tetap muncul di daftar, tetapi gagal saat dijalankan.
- Cek lisensi KAPE untuk penggunaan di konteksmu (bagian 1.2) [S3][S11].

**Kapan gagal:** daftar kosong atau jauh lebih pendek dari yang diharapkan biasanya berarti folder `Targets` atau `Modules` tidak lengkap, atau `--sync` gagal di tengah jalan.

### 2.5 Volatility 3 di `jkt-dfir02` (tanpa internet)

Langkah ini menyiapkan Volatility 3 untuk pertanyaan lanjutan retainer tentang memori laptop (E01, E08, E13), dan menjawab bagian pertanyaan ketiga yang sering terlupa: data yang diunduh saat alat berjalan.

**Tujuan:** memasang Volatility 3 di virtualenv, memverifikasinya, dan menyiapkan symbol table Windows secara offline.

```bash
python3 -m venv ~/venv/vol3 && . ~/venv/vol3/bin/activate
pip install volatility3
pip show volatility3 | grep -i '^version'
vol -h
vol -f /dev/null windows.info
```

- Volatility 3 butuh Python 3.8.0 atau lebih baru, tersedia di PyPI sebagai `volatility3`, dan README proyek menyarankan virtual environment supaya dependensinya terpisah dari paket sistem [S9].
- `pip install` butuh akses ke PyPI, jadi dijalankan di jendela proxy, atau paketnya diunduh dulu di mesin lain lalu dipasang dari berkas lokal.
- `pip show`: versi terpasang untuk inventaris. Harus 2.28.2 [S1].
- `vol -h` menampilkan bantuan dan daftar plugin. Bila Volatility dipasang dari source, perintahnya `python3 vol.py -h`.
- Perintah terakhir akan gagal (bukan image valid), tetapi error yang benar menandakan Volatility berjalan. Image memori nyata dipakai di Day 14.

Keluaran ilustrasi:

```
Version: 2.28.2
Volatility 3 Framework 2.28.2
...
```

Untuk simbol, README menyediakan symbol pack Windows (`windows.zip`, rilis v0.0.1 di repo `volatility3-test-data`) beserta berkas SHA256SUMS, dan berkas zip itu ditaruh dengan nama aslinya di direktori `volatility3/symbols` [S9]. Volatility menerima symbol table berbentuk `.json`, `.json.gz`, `.json.xz`, atau zip berisi berkas tersebut, dan menyimpan cache di `~/.cache/volatility3` [S10]. Hash `windows.zip` dicek terhadap SHA256SUMS sebelum dipindahkan ke `jkt-dfir02`.

```bash
sha256sum -c SHA256SUMS --ignore-missing
```

- `--ignore-missing`: hanya memeriksa berkas yang ada di folder, karena SHA256SUMS juga memuat pack macOS dan Linux yang tidak diunduh.

**Cara membaca hasil:** `windows.zip: OK` berarti pack yang dipindahkan identik dengan yang diterbitkan.

**Kapan gagal:** symbol pack adalah snapshot pada satu waktu, jadi bisa tidak memuat build Windows yang lebih baru dari pack itu; cek apakah build laptop PT JAB tercakup dengan menjalankan `windows.info` pada image. Bila tidak tercakup, dua jalan yang sah: buka jendela proxy khusus ke Microsoft Symbol Server agar Volatility mengunduh PDB yang dibutuhkan [S10], atau unduh PDB di mesin lain lalu konversi dengan `pdbconv.py` yang dibawa Volatility [S10]. Jalan yang tidak sah adalah menyalin image memori ke laptop yang punya internet.

### 2.6 Plaso di `jkt-dfir02` lewat Docker

Plaso disiapkan untuk super-timeline (Day 13) bila retainer meminta timeline gabungan. Image Docker membuat versi mudah dibekukan, asalkan yang dicatat adalah digest, bukan hanya tag.

```bash
docker pull log2timeline/plaso
docker images --digests log2timeline/plaso
docker run log2timeline/plaso log2timeline.py --version
```

- `docker pull log2timeline/plaso`: image resmi di Docker Hub [S15]. Dijalankan di jendela proxy.
- `docker images --digests`: digest image untuk inventaris.
- `log2timeline.py --version` di dalam container: uji yang disarankan dokumentasi Plaso [S15]. Versi yang diharapkan saat catatan ini ditulis: 20260720, rilis stabil terbaru [S16].
- Saat dipakai, bukti dan output diakses lewat volume, misalnya `-v /data/:/data`; di sistem dengan SELinux, opsi `:z` pada volume kemungkinan diperlukan [S15].

**Kapan gagal:** tag `latest` menunjuk pre-release atau versi lain dari yang diuji. Bila versi yang tampil bukan yang dicatat, pakai image berdasarkan digest.

### 2.7 Velociraptor: verifikasi biner di lab

Velociraptor disiapkan di toolkit `jkt-evid01:/export/irkit` dan diuji di `LAB-DFIR01`. Server kasus dibangun sore hari di Day 04; hari ini cukup memastikan biner 0.77.3 berjalan.

```
velociraptor version
velociraptor gui
```

- `version` memastikan biner berjalan (harus 0.77.3) [S4].
- `gui` menyalakan GUI, frontend, dan satu client lokal dalam satu mesin, sehingga artifact bisa dikumpulkan dari mesin itu sendiri seperti dari endpoint biasa [S17]. Mode ini hanya untuk lab; server penuh dengan client dibangun di Day 04.
- Dokumentasi quickstart menyebut client Windows minimal Windows 10 [S18].
- Cek subcommand persis dengan `velociraptor --help` atau `velociraptor -h` di versi lab.

**Kapan gagal:** biner lama dari toolkit dipakai karena "sudah ada". Velociraptor sebelum 0.77.3 terdampak CVE yang diperbaiki di rilis itu [S4][S18].

### 2.8 Mount read-only dan struktur folder kasus (08:20)

Langkah terakhir menjawab pertanyaan kelima dan keenam Yoga sekaligus.

**Tujuan:** membuat area kerja kasus, me-mount share bukti read-only di kedua workstation, dan memastikan container salinan kerja di-mount read-only.

Struktur folder di `jkt-evid01`:

```
/evidence/INC-2026-019/                 MASTER. Share \\jkt-evid01\evidence, read-only untuk analyst
  E01/ ... E14/                         bukti + <berkas>.sha256 (E15, E16 masuk siang ini)
  evidence-log.csv                      nomor bukti, hash, waktu, pemegang
/cases/INC-2026-019/                    AREA KERJA. Share \\jkt-evid01\cases, read-write untuk analyst kasus
  work/                                 salinan kerja (E14-W1 dibuat setelah verifikasi 08:52)
  analysis/E14-W1/EZ-2026.5.0/          hasil parser, folder memuat nomor bukti dan versi alat
  notes/case-notes.md                   catatan kasus (Day 01)
  tools/tool-inventory-2026-10-15.csv   salinan inventaris alat saat kasus diolah
```

- Pemisahan `/evidence` (master, read-only) dan `/cases` (hasil kerja) mencegah pencemaran bukti (Day 01).
- Berkas `.sha256` di tiap folder bukti memegang hash koleksi.
- Folder hasil yang memuat versi alat membuat retainer tidak perlu bertanya "pakai versi berapa".

Mount di `jkt-dfir02` (Linux):

```bash
sudo mount -t cifs //jkt-evid01/evidence /mnt/evidence -o ro,username=<akun-analyst>
mount | grep /mnt/evidence
```

- `-o ro`: read-only dari sisi klien, lapis kedua setelah izin share [S21].
- `mount | grep`: pastikan baris mount memuat `ro`. Uji sengaja dengan `touch /mnt/evidence/uji` harus ditolak.

Mount container salinan kerja di `JKT-DFIR01` (Windows, sebagai administrator):

```powershell
Mount-DiskImage -ImagePath '\\jkt-evid01\cases\INC-2026-019\work\<container>.vhdx' -Access ReadOnly -PassThru
Dismount-DiskImage -ImagePath '\\jkt-evid01\cases\INC-2026-019\work\<container>.vhdx'
```

- `-Access ReadOnly`: wajib ditulis. Tanpa parameter ini, VHD/VHDX di-mount read-write [S20].
- `-PassThru`: menampilkan objek image yang di-mount, untuk dicatat.
- Mount VHD membutuhkan hak administrator [S20].
- Apakah `Mount-DiskImage` bisa me-mount VHDX langsung dari path share SMB perlu dicek di lingkunganmu; bila tidak, salin container salinan kerja ke disk lokal `JKT-DFIR01` dan hash ulang setelah disalin. Nama container persis dibahas di Day 03.

Keluaran ilustrasi (catatan 08:20 sampai 08:45):

```
08:21  jkt-dfir02: /mnt/evidence mounted (ro); touch ditolak: Read-only file system
08:24  JKT-DFIR01: \\jkt-evid01\evidence terpasang sebagai Z: (izin baca saja; uji tulis ditolak)
08:30  /cases/INC-2026-019/ dibuat; tool-inventory-2026-10-15.csv disalin ke tools/
08:45  Status ke Yoga: JKT-DFIR01 dan jkt-dfir02 siap; versi dibekukan sampai INC-2026-019 ditutup
```

**Cara membaca hasil:** baris "uji tulis ditolak" adalah bukti bahwa kontrol bekerja, bukan sekadar dikonfigurasi. Simpan baris itu di catatan kasus.

**Kapan gagal:** analyst me-mount share dengan akun yang ternyata punya izin tulis (misalnya akun admin), sehingga lapis pertama hilang tanpa terasa. Mount bukti selalu dengan akun analyst biasa, bukan `adm.<nama>`.

## 3. Lab praktik (di VM lab terisolasi)

**Prasyarat:** hypervisor (VirtualBox/VMware/Hyper-V); ISO Windows untuk VM korban; VM analisis Windows dengan .NET 9 Desktop runtime; VM Linux (Ubuntu LTS) bila ingin menguji Volatility 3 dan Plaso; akses internet hanya di VM analisis untuk mengunduh alat (dari sumber resmi, oleh kamu sendiri), lalu diputus. Pakai nama yang sama dengan PT JAB supaya lab-mu meniru situasi Day ini: `LAB-WS01`, `LAB-DFIR01`, jaringan host-only `172.16.50.0/24`, folder kasus `CASE-2026-LAB-002`.

1. **Topologi.** Buat `LAB-WS01` (Windows 11 + Sysmon + audit policy, bagian 1.4) dan `LAB-DFIR01`. Set jaringan keduanya ke host-only `172.16.50.0/24`. Pastikan `LAB-WS01` tidak bisa menjangkau internet (uji DNS dan HTTP ke luar harus gagal). Ambil snapshot bersih keduanya dengan nama bertanggal.
2. **EZ Tools.** Jalankan Get-ZimmermanTools ke folder bertanggal (bagian 2.2) di `LAB-DFIR01`. Verifikasi MFTECmd, EvtxECmd, RECmd, PECmd menampilkan versi.
3. **KAPE.** Pasang KAPE; jalankan `--sync`, `--tlist`, dan `--mlist` (bagian 2.2 dan 2.4). Catat lisensi yang berlaku untuk lab pribadimu (bagian 1.2).
4. **Volatility 3.** Pasang Volatility 3 di virtualenv; verifikasi versi (bagian 2.5). Unduh symbol pack Windows, verifikasi dengan SHA256SUMS, lalu putus internet dan jalankan `windows.info` pada `/dev/null` untuk melihat error yang benar.
5. **Velociraptor.** Pasang biner Velociraptor; verifikasi versi dan mode GUI (bagian 2.7). Server penuh di Day 04.
6. **Inventaris.** Buat `tool-inventory.csv` dengan kolom: mesin, alat, versi, sumber unduhan, SHA-256 arsip, tanggal, lisensi (bagian 2.1). Di lab pribadi, simpan di satu tempat tetap, misalnya `C:\DFIR\docs\`, berdampingan dengan `C:\DFIR\tools\` (alat per tanggal update) dan `C:\DFIR\datasets\` (dataset publik).
7. **Uji regresi.** Jalankan aktivitas yang jamnya kamu catat di `LAB-WS01` (bagian 2.3), ekspor event log, salin ke `LAB-DFIR01`, hash, lalu proses dengan dua versi EvtxECmd bila ada (atau dengan dan tanpa maps terbaru). Bandingkan jumlah baris dan pastikan aktivitasmu muncul dengan jam UTC yang benar.
8. **Struktur dan hash.** Buat struktur folder kasus `CASE-2026-LAB-002` yang meniru bagian 2.8 (`evidence\`, `work\`, `analysis\<bukti>\<versi alat>\`, `notes\`, `tools\`). Hash koleksi dan simpan ke berkas `.sha256`.
9. **Read-only.** Buat VHDX kecil berisi salinan event log, mount dengan `Mount-DiskImage -Access ReadOnly`, coba tulis berkas (harus gagal), dismount. Ulangi tanpa `-Access` dan amati bahwa tulis berhasil. Hash VHDX sebelum dan sesudah kedua percobaan, lalu catat mana yang mengubah hash.
10. **Dataset.** Ambil satu dataset publik kecil (cek lisensi) atau pakai koleksi dari langkah 7. Parse `$MFT` atau satu event log dengan EZ Tools dan buka di Timeline Explorer.

Untuk langkah 10, contoh perintahnya:

```
MFTECmd.exe -f "C:\CASE-2026-LAB-002\work\C\$MFT" --csv "C:\CASE-2026-LAB-002\analysis\MFT\EZ-2026.5.0" --csvf mft.csv
```

- Hasil CSV dibuka di Timeline Explorer. Bila baris muncul dan timestamp terbaca, parser berfungsi.
- Ini sekaligus latihan alur: koleksi (Day 03), parse (EZ Tools), baca (Timeline Explorer).
- Cek path `$MFT` dalam struktur koleksi KAPE/Velociraptor lab-mu.

**Hasil yang sebaiknya tersimpan:**

- `LAB-WS01` dan `LAB-DFIR01` berjalan; `LAB-WS01` terisolasi (bukti uji gagal ke luar); snapshot bersih diambil.
- EZ Tools terpasang di folder bertanggal; minimal empat parser menampilkan versi.
- KAPE mengenali Target dan Module; lisensi dicatat.
- Volatility 3 2.28.x dan Velociraptor 0.77.x terverifikasi; symbol pack terverifikasi hash-nya.
- Inventaris alat terisi lengkap, termasuk hash arsip unduhan.
- Catatan uji regresi: jumlah baris per versi dan aktivitas yang ditemukan.
- Struktur folder kasus dan berkas `.sha256` dibuat.
- Catatan percobaan VHDX: hash tetap sama dengan `-Access ReadOnly`, berubah tanpa parameter itu.
- Satu dataset diparse dan dibaca di Timeline Explorer.

**Variasi tantangan:** buat skrip koleksi hash sederhana yang menghitung SHA256 semua file di folder `evidence` dan menyimpannya ke berkas hash, lalu skrip verifikasi yang membandingkan ulang. Jalankan verifikasi setelah menyalin bukti ke folder `work` dan pastikan hash cocok. Tambahkan satu kolom ke keluaran skrip: versi skrip itu sendiri, supaya alat buatanmu juga masuk inventaris.

## 4. Troubleshooting

Tabel ini memuat masalah yang sering muncul saat menyiapkan dan merawat workstation analisis. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| EZ Tool tidak jalan | Runtime .NET 9 belum terpasang | Pasang .NET 9; atau pakai `-NetVersion 4` [S2] |
| Timeline Explorer atau Registry Explorer tidak terbuka padahal tool CLI jalan | Hanya runtime .NET biasa yang terpasang, bukan Desktop runtime | Pasang .NET 9 Desktop runtime [S2] |
| Get-ZimmermanTools gagal | Eksekusi skrip diblokir; tanpa internet | Izinkan skrip; jalankan di jendela proxy atau di VM analisis yang punya akses unduh |
| KAPE tidak menampilkan Target | Folder Targets/Modules tidak lengkap | Perbarui KAPE (`--sync`); cek struktur folder [S12] |
| Module KAPE gagal walau muncul di `--mlist` | Biner tool tidak ada di `Modules\bin` | Taruh biner yang dibutuhkan di `\KAPE\Modules\bin` [S13] |
| Hasil `!EZParser` berbeda dengan EZ Tools berdiri sendiri | Salinan EZ Tools di `Modules\bin` beda versi | Inventaris kedua lokasi (bagian 2.1); samakan versi |
| Volatility error import | Dependensi Python kurang | Pasang di virtualenv; `pip install volatility3` atau `pip install -r requirements.txt` dari folder Volatility 3 [S1][S9] |
| Volatility berhenti dengan pesan symbol table tidak ditemukan | Mesin tanpa internet tidak bisa mengunduh PDB dari Microsoft Symbol Server | Symbol pack offline, jendela proxy ke symbol server, atau `pdbconv.py` (bagian 2.5) [S9][S10] |
| Velociraptor GUI tidak terbuka | Perintah beda versi | `velociraptor -h` untuk melihat subcommand yang tersedia di versi lab [S4] |
| Container Plaso tidak bisa membaca folder bukti | Volume tidak di-mount, atau SELinux memblokir | Cek `-v`; tambahkan `:z` di sistem SELinux [S15] |
| Hash VHDX salinan kerja berubah setelah dibuka | Di-mount tanpa `-Access ReadOnly` | Buat salinan kerja baru dari master; mount dengan `-Access ReadOnly` [S20] |
| Hash image ext4 berubah walau di-mount `ro` | Journal di-replay karena filesystem dirty | `ro,noload` atau `blockdev` read-only; buat salinan baru dari master [S21] |
| Timeline Explorer kosong | CSV salah atau parse gagal | Cek keluaran EZ Tool; pastikan path artefak benar |

## 5. Kesalahan umum dan jebakan

- **Menganalisis di VM korban.** Analisis di VM terpisah; korban hanya menghasilkan artefak.
- **VM korban terhubung internet saat skenario.** Isolasi; aktivitas uji dan sampel tidak boleh bocor.
- **Tidak snapshot sebelum skenario.** Tanpa snapshot bersih, lab cepat kotor dan hasil tidak bisa diulang.
- **Memakai dataset tanpa cek lisensi.** Banyak dataset gratis untuk latihan tetapi tidak untuk redistribusi; cek sebelum publikasi.
- **Tidak mencatat versi alat.** Hasil forensik bergantung versi; catat untuk reproduksibilitas.
- **Memakai KAPE edisi gratis untuk pekerjaan perusahaan.** Edisi Solo untuk penggunaan non-komersial; pekerjaan perusahaan butuh Enterprise License [S11].
- **Update di tengah kasus tanpa uji dan catatan.** Hasil sebelum dan sesudah update tidak lagi sebanding, dan tidak ada yang tahu kenapa.
- **Menganggap `ro` sebagai jaminan.** Filesystem tertentu tetap bisa ditulis saat di-mount read-only [S21], dan `Mount-DiskImage` tanpa `-Access` me-mount VHDX read-write [S20]. Hash tetap jadi pembuktinya.
- **Membuka jalur internet permanen untuk "sekali unduh".** Jendela proxy yang tidak pernah ditutup mengubah workstation analisis menjadi mesin biasa.
- `[komunitas, belum terkonfirmasi]` Banyak praktisi memakai Get-ZimmermanTools untuk menjaga EZ Tools tetap terbarui, dan menjalankan KAPE plus EZ Tools di VM analisis Windows terpisah dari korban. Pola ini umum; sesuaikan dengan hypervisor dan sumber daya lab-mu [S2][S3].

## 6. Catatan terkini

Bagian ini mencatat versi dan perubahan alat per 2026-10-16. Gunakan untuk mengisi kolom versi inventaris; perubahan yang memengaruhi perintah sudah dibahas di bagian 1 dan 2.

- **Volatility 3 2.28.2 (17 Sep 2026)** masih rilis terbaru: menambah renderer Mermaid dan verifikasi layer Intel Windows lewat pemeriksaan translasi; analisis macOS kini memberi peringatan deprecation; output Arrow tidak didukung di executable karena dependensinya kira-kira menggandakan ukuran biner [S1]. Rilis sebelumnya: 2.28.0 (30 Apr) dan 2.27.0 (29 Jan) [S1].
- **EZ Tools** default ke build .NET 9; GUI (Timeline Explorer, Registry Explorer) hanya .NET 9; versi tool utama 2026.5.0 per 2026-10-16 [S2].
- **Velociraptor 0.77.3 (5 Okt 2026)** adalah rilis bugfix untuk CVE di siklus rilisnya, menambah `Azure.Monitor.Upload`, dan mengubah kolom output artifact backup server [S4]. Dokumentasi quickstart memasang banner agar pengguna memperbarui ke 0.77.3, walaupun contoh perintahnya masih menunjuk 0.75.6 [S18].
- **Plaso:** rilis stabil 20260720; 20260928 masih pre-release [S16].
- **KAPE** tetap gratis untuk penggunaan non-komersial (edisi Solo); penggunaan komersial butuh Enterprise License. EULA Solo terakhir diubah 2020-06-04 [S11]. FAQ dokumentasi KAPE (diperbarui Februari 2026) menyebut penggunaan internal perusahaan gratis dan penggunaan komersial (jaringan pihak ketiga atau engagement berbayar) tidak lagi tersedia sejak 1 Januari 2026 [S24]; perbedaan dengan EULA ini perlu dipantau. Halaman produk Kroll menolak akses otomatis saat dicek ulang 2026-10-16, sehingga nomor versi KAPE terbaru perlu dicek langsung dari header `kape.exe` setelah update.
- **Sysmon:** halaman Microsoft Learn terbit 2026-09-10 dan menyebut Sysmon berjalan di Windows 11 dan Windows Server 2019 ke atas [S6]. Sejak Februari 2026, Microsoft menguji Sysmon bawaan Windows 11 di Insider build 26220.7752 (Beta) dan 26300.7733 (Dev): mati secara bawaan, dinyalakan lewat Optional features atau `Dism /Online /Enable-Feature /FeatureName:Sysmon` lalu `sysmon -i`, dan Sysmon dari Sysinternals harus di-uninstall dulu [S22]. Status rilis umumnya perlu dicek di dokumentasi Microsoft sebelum dipakai di `LAB-WS01`.

## 7. Cheat sheet

```
TOPOLOGI   bukti (master, read-only) | analisis (JKT-DFIR01 Win, jkt-dfir02 Linux; tidak join domain; proxy per jendela)
           lab terisolasi (host-only, tanpa rute ke produksi): VM korban + VM analisis lab ; alat masuk lewat disk virtual
ALAT       EZ Tools 2026.5.0 (.NET 9; GUI butuh Desktop runtime) | KAPE (Solo = non-komersial; perusahaan = Enterprise)
           Volatility3 2.28.2 (Python >= 3.8, venv) | Velociraptor 0.77.3 (CVE) | Plaso 20260720 (bukan pre-release)
EZ TOOLS   MFTECmd | RECmd/Registry Explorer | PECmd | AppCompatCacheParser | AmcacheParser | EvtxECmd | JLECmd/LECmd | SBECmd | SrumECmd | Timeline Explorer
UPDATE     Get-ZimmermanTools.ps1 -Dest <folder-bertanggal> -NetVersion 9
           kape.exe --sync (Target/Module) ; Modules\bin = salinan EZ terpisah ; maps/batch ikut update
           Vol3: symbol pack offline + SHA256SUMS, atau jendela ke MS Symbol Server, atau pdbconv.py
           update sebelum kasus -> uji di lab -> catat -> bekukan ; versi lama tidak ditimpa
INVENTARIS mesin | alat | versi | sumber | SHA-256 arsip | tanggal | lisensi ; salin ke folder kasus
           Win: (Get-Item x.exe).VersionInfo.FileVersion ; Linux: pip show volatility3 ; docker images --digests
UJI        data yang kamu kenal (aktivitas dengan jam tercatat) ; versi lama vs baru ; Sysmon UTC, EID 3 mati default
READ-ONLY  1 izin share server | 2 mount ro klien (ext4: ro,noload) ; Mount-DiskImage -Access ReadOnly | 3 hash
FOLDER     /evidence/<kasus>/ master + .sha256 | /cases/<kasus>/ work, analysis/<bukti>/<versi alat>, notes, tools
AMAN       korban terisolasi + snapshot ; analisis tidak eksekusi sampel ; image/sampel = data
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Share `\\jkt-evid01\evidence` sudah di-mount read-only, jadi master pasti tidak berubah dan hash tidak perlu diverifikasi lagi." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Read-only mount adalah satu dari tiga lapis kontrol, bukan bukti. Halaman manual `mount` memperingatkan bahwa filesystem tertentu tetap bisa ditulis walau di-mount `ro` (ext3/ext4 me-replay journal bila dirty), dan `Mount-DiskImage` tanpa `-Access ReadOnly` me-mount VHDX read-write. Yang membuktikan master tidak berubah adalah hash yang diverifikasi sebelum salinan kerja dibuat dan saat kasus ditutup. Lihat bagian 1.5.

</details>

**2. Skenario keputusan.** Hari ketiga `INC-2026-019`, EZ Tools versi baru dirilis. E14 sudah diproses dengan versi yang dibekukan Kamis pagi. Apa yang kamu lakukan?

- A. Langsung update, karena versi terbaru selalu paling akurat.
- B. Tetap di versi yang dibekukan; update hanya bila perubahan versi baru memengaruhi artefak yang sedang dianalisis, dan bila begitu, uji di lab, catat, lalu tandai atau proses ulang bukti yang sudah diolah dengan versi lama.
- C. Jangan pernah update selama kasus apa pun alasannya.

<details><summary>Jawaban</summary>

B. Pembekuan versi menjaga hasil sebanding dan bisa direproduksi, tetapi bukan larangan mutlak: bug yang memengaruhi artefak kasus atau celah keamanan adalah alasan sah, asal melalui uji dan catatan. A keliru karena update tanpa uji membuat hasil sebelum dan sesudahnya tidak sebanding dan tidak ada yang tahu kenapa. C keliru karena mengabaikan bug atau CVE yang relevan juga bisa merusak hasil, seperti Velociraptor sebelum 0.77.3. Lihat bagian 1.3.

</details>

**3. Pertanyaan jebakan.** "KAPE bisa diunduh gratis dari Kroll, jadi PT JAB boleh memakainya untuk mengolah bukti insiden tanpa lisensi apa pun." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Edisi gratis (KAPE Solo) hanya untuk tujuan non-komersial seperti pemakaian pribadi, lembaga penegak hukum pemerintah, dan pendidikan. Penggunaan untuk tujuan bisnis, termasuk mengolah bukti insiden perusahaan, membutuhkan KAPE Enterprise License, yang juga membatasi jumlah pengguna sesuai order. FAQ dokumentasi 2026 lebih longgar untuk penggunaan internal perusahaan, tetapi selama EULA belum berubah PT JAB memakai tafsir yang lebih ketat. Lihat bagian 1.2.

</details>

**4. Skenario keputusan.** Retainer meminta kamu memastikan E13 (memori `JKT-WS-0412`) terbaca. Di `jkt-dfir02`, `windows.info` gagal karena symbol table tidak ditemukan. Pilihan mana yang tepat?

- A. Salin E13 ke laptop kantor yang punya internet supaya Volatility bisa mengunduh simbol.
- B. Pakai symbol pack Windows offline yang hash-nya sudah diverifikasi; bila build laptop tidak tercakup, buka jendela proxy khusus ke Microsoft Symbol Server atau konversi PDB yang diunduh di mesin lain dengan `pdbconv.py`, lalu catat langkahnya.
- C. Buka akses internet penuh di `jkt-dfir02` supaya masalah ini tidak terulang.

<details><summary>Jawaban</summary>

B. Masalahnya ada pada data yang biasanya diunduh Volatility saat berjalan, jadi solusinya membawa data itu ke mesin dengan cara yang terkendali dan tercatat. A keliru karena memindahkan bukti ke mesin yang tidak dirancang untuk bukti dan tersambung ke internet. C keliru karena mengubah workstation analisis menjadi mesin biasa secara permanen untuk masalah yang cukup diselesaikan sekali. Lihat bagian 1.3 dan 2.5.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Dimas Prasetyo (SOC lead, IC), dalam tiga kalimat, kenapa alat diuji di lab dulu walaupun E14 sudah menunggu dan waktu sempit.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Di lab kita menjalankan alat pada aktivitas yang kita buat sendiri dan tahu jamnya, jadi kalau hasilnya salah, kita tahu masalahnya di alat, bukan di bukti. Kalau langsung ke E14, hasil yang aneh tidak bisa dibedakan antara jejak penyerang dan alat yang rusak setelah update. Ujinya empat puluh menit sebelum imaging mulai, dan hasilnya kita lampirkan supaya retainer tidak meragukan CSV kita."

Kesalahan yang sering muncul:
- Menjelaskan detail versi dan maps, padahal Dimas butuh alasan dan biayanya dalam waktu.
- Menjanjikan bahwa uji membuktikan alat benar untuk semua artefak, padahal uji hanya mencakup artefak yang diuji.
- Tidak menyebut manfaatnya bagi pihak lain (retainer, DPO).

</details>

**6. Pertanyaan jebakan.** "Inventaris EZ Tools di `C:\DFIR\tools\EZTools` sudah menunjukkan 2026.5.0, jadi hasil Module `!EZParser` KAPE pasti dari versi 2026.5.0." Benarkah?

<details><summary>Jawaban</summary>

Tidak. KAPE menjalankan salinan EZ Tools di `KAPE\Modules\bin`, yang terpisah dari folder EZ Tools berdiri sendiri dan tidak diperbarui oleh `kape.exe --sync`. Kedua lokasi harus diinventaris dan disamakan versinya. Lihat bagian 1.3 dan 2.1.

</details>

**7. Interview question (English).** "How do you set up and maintain a forensic analysis workstation so that your results hold up when someone else checks them?"

<details><summary>Sample answer</summary>

"I start with separation: the analysis workstation isn't domain joined, has no general internet access, and evidence sits on a separate store where analysts only have read access. Tools are tested in an isolated lab first, on activity I generated myself and timed, so I know what the output should be. I keep an inventory per machine with tool, version, download source, hash of the download and license, and I copy it into the case folder when a case starts. I update before a case begins and then freeze versions until it closes; if I must update mid-case, I test, document it, and reprocess or flag earlier results. Evidence is opened through three layers, share permissions, read-only mounts, and hash verification, because read-only mounts alone aren't a guarantee. And output folders are named by evidence ID and tool version, so another examiner can reproduce exactly what I did."

What makes this answer strong: it treats reproducibility as the goal, names concrete controls (isolation, inventory, version freeze, layered read-only), admits the limits of a read-only mount, and ties everything to someone else being able to check the work.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Volatility 3 releases (2.28.2) | https://github.com/volatilityfoundation/volatility3/releases | primer | 2.28.2, 17 Sep 2026; diakses 2026-10-09, dicek ulang 2026-10-16 | Tinggi. Versi, plugin, perubahan; rename plugin ke subpaket `malware` di 2.26.2 |
| S2 | Eric Zimmerman tools (daftar dan Get-ZimmermanTools) | https://ericzimmerman.github.io/ | primer | diakses 2026-10-09, dicek ulang 2026-10-16 | Tinggi. Tool, .NET 4.7.2 dan .NET 9, GUI hanya .NET 9, Desktop runtime, `-Dest`, `-NetVersion`, versi 2026.5.0 |
| S3 | KAPE (Kroll) | https://www.kroll.com/en/services/cyber/incident-response-litigation-support/kroll-artifact-parser-extractor-kape | primer (vendor) | diakses 2026-10-09; menolak akses otomatis (403) saat dicek ulang 2026-10-16 | Tinggi untuk fungsi; lisensi dikonfirmasi lewat S11 |
| S4 | Velociraptor releases dan dokumentasi | https://github.com/Velocidex/velociraptor/releases | primer | 0.77.3, 5 Okt 2026; diakses 2026-10-09, dicek ulang 2026-10-16 | Tinggi. Rilis bugfix CVE (ID CVE ada di advisory yang ditautkan), perubahan artifact |
| S5 | Plaso / Timesketch (untuk Day 13) | https://plaso.readthedocs.io/ | primer | diakses 2026-10-09 | Tinggi; dipakai di Day 13 |
| S6 | Microsoft Learn: Sysmon | https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon | primer | terbit 2026-09-10; diakses 2026-10-10, dicek ulang 2026-10-16 | Tinggi. Daftar event ID, default SHA1 dan tanpa jaringan, EID 3 mati default, `sysmon -c`, timestamp UTC, OS yang didukung |
| S7 | Microsoft Learn: Command line process auditing | https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing | primer | diakses 2026-10-10 | Tinggi. Setting command line di 4688 |
| S8 | Atomic Red Team (Red Canary) | https://github.com/redcanaryco/atomic-red-team | primer | diakses 2026-10-10 | Tinggi. Struktur test per teknik, GUID, cleanup |
| S9 | Volatility 3 README (GitHub) | https://github.com/volatilityfoundation/volatility3 | primer | diakses 2026-10-16 | Tinggi. Python 3.8.0 ke atas, `pip install volatility3`, virtualenv, symbol pack v0.0.1 dan SHA256SUMS, lokasi `volatility3/symbols` |
| S10 | Volatility 3 documentation: Symbol Tables | https://volatility3.readthedocs.io/en/latest/symbol-tables.html | primer | diakses 2026-10-16 | Tinggi. Pencarian simbol lokal, unduh PDB dari Microsoft Symbol Server, format, cache, `pdbconv.py` |
| S11 | Kroll: End User License Agreement (KAPE Solo Edition) | https://www.kroll.com/en/end-user-license-agreement | primer (vendor) | terakhir diubah 2020-06-04; diakses 2026-10-16 | Tinggi. Solo untuk non-komersial; komersial butuh Enterprise License |
| S12 | KapeFiles (GitHub) | https://github.com/EricZimmerman/KapeFiles | primer | diakses 2026-10-16 | Tinggi. `kape.exe --sync` dan Sync with GitHub di gkape |
| S13 | SANS ISC: KAPE (Kroll Artifact Parser and Extractor) | https://isc.sans.edu/diary/25258 | sekunder | 2019-08-21 (lebih dari 3 tahun); diakses 2026-10-16 | Sedang. `Get-KAPEUpdate.ps1`, `--sync`, biner pihak ketiga di `Modules\bin` |
| S14 | KAPE-EZToolsAncillaryUpdater (GitHub) | https://github.com/AndrewRathbun/KAPE-EZToolsAncillaryUpdater | sekunder (skrip komunitas) | diakses 2026-10-16 | Sedang. Memperbarui KAPE, `Modules\bin`, maps, batch file; README menyebut build .NET 6 sejak versi 4.0, berbeda dengan build yang kini ditawarkan S2 |
| S15 | Plaso documentation: Installing with Docker | https://plaso.readthedocs.io/en/latest/sources/user/Installing-with-docker.html | primer | diakses 2026-10-16 | Tinggi. Image `log2timeline/plaso`, uji `--version`, volume, `:z` untuk SELinux |
| S16 | Plaso releases (GitHub) | https://github.com/log2timeline/plaso/releases | primer | diakses 2026-10-16 | Tinggi. 20260720 rilis stabil; 20260928 pre-release |
| S17 | Velociraptor README (GitHub) | https://github.com/Velocidex/velociraptor | primer | diakses 2026-10-16 | Tinggi. `velociraptor gui` menyalakan GUI, frontend, dan client lokal |
| S18 | Velociraptor documentation: Quickstart | https://docs.velociraptor.app/docs/deployment/quickstart/ | primer | diakses 2026-10-16 | Tinggi. Banner update ke 0.77.3 karena CVE; client Windows minimal Windows 10; contoh perintah masih 0.75.6 |
| S19 | Microsoft Learn: Get-FileHash | https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-filehash | primer | PowerShell 7.6, ms.date 2022-12-12; diakses 2026-10-16 | Tinggi. Default SHA256, membandingkan dengan hash terbitan |
| S20 | Microsoft Learn: Mount-DiskImage | https://learn.microsoft.com/en-us/powershell/module/storage/mount-diskimage | primer | ms.date 2016-12-20 (lebih dari 3 tahun, dokumen Windows Server 2025); diakses 2026-10-16 | Tinggi. `-Access` ReadOnly/ReadWrite, default read-write untuk VHD, ISO selalu read-only, butuh administrator |
| S21 | mount(8), Linux manual page | https://man7.org/linux/man-pages/man8/mount.8.html | primer | diakses 2026-10-16 | Tinggi. `ro` bisa tetap menulis; ext3/ext4 replay journal; `ro,noload`, `blockdev` |
| S22 | BleepingComputer: Microsoft rolls out native Windows 11 Sysmon security monitoring | https://bleepingcomputer.com/news/microsoft/microsoft-rolls-out-native-windows-11-sysmon-security-monitoring | sekunder (media) | 2026-02-04; diakses 2026-10-16 | Sedang. Insider build, cara menyalakan, uninstall Sysmon lama dulu; status rilis umum belum dikonfirmasi primer |
| S23 | Kroll: KAPE Enterprise License Terms and Conditions | https://www.kroll.com/en/kape-enterprise-license-terms-conditions | primer (vendor) | diakses 2026-10-16 | Tinggi. Pemakaian di jaringan pemegang lisensi, jumlah pengguna sesuai order, tidak bisa dialihkan tanpa persetujuan tertulis |
| S24 | KAPE documentation: Frequently asked questions | https://raw.githubusercontent.com/EricZimmerman/KapeDocs/master/Pages/50-Frequently-asked-questions.md | primer (dokumentasi resmi) | diperbarui 2026-02-11; diakses 2026-10-16 | Tinggi. Gratis untuk pemerintah, pendidikan, riset, dan penggunaan internal perusahaan; tidak lagi tersedia untuk penggunaan komersial sejak 2026-01-01. Tidak sejalan dengan EULA Solo [S11] |

**Catatan sumber:** lisensi KAPE untuk penggunaan komersial dikonfirmasi dari EULA Solo [S11], tetapi FAQ dokumentasi 2026 [S24] lebih longgar untuk penggunaan internal perusahaan; tafsir ketat PT JAB adalah pilihan kasus fiktif, bukan kesimpulan hukum; rincian ketentuan Enterprise (harga, jumlah pengguna) perlu dikonfirmasi langsung ke Kroll sebelum dipakai di pekerjaan. Dataset publik spesifik tidak diinventarisasi di sini; lisensi tiap dataset harus dicek sendiri. Catatan rilis Volatility 3 2.28.x tidak menyebut versi Python minimum; README menyebut 3.8.0 ke atas [S9]. Perintah Velociraptor persis (`gui`, `version`) perlu dicek dengan `velociraptor -h` di versi lab. Nama skrip `Get-KAPEUpdate.ps1` berasal dari sumber 2019 [S13] dan README skrip komunitas [S14]; cek apakah masih dibawa di paket KAPE terbaru. Cakupan build Windows di symbol pack Volatility v0.0.1 tidak tercantum di README, jadi kemungkinan build baru tidak tercakup adalah penalaran, bukan pernyataan sumber. Sysmon bawaan Windows 11 baru dikonfirmasi oleh sumber media untuk Insider build [S22]. Topologi, nama mesin, jendela proxy, struktur folder, dan semua keluaran PT JAB adalah contoh fiktif, bukan konfigurasi resmi sumber mana pun.
