---
day: 13
title: 'Hunting living-off-the-land dan abuse script: LOLBin, signed binary proxy, binary yang diganti nama, dan script host'
researched_on: 2026-10-18
versions_checked: 'MITRE ATT&CK v20 (T1218 versi 4.0 diubah 2026-05-12, 14 sub-teknik, taktik Stealth TA0005; T1218.011 versi 3.0; T1036.003 versi 3.0; T1036.005 versi 3.0 diubah 2026-09-11; T1059.001 versi 1.6 diubah 2026-09-18; T1059.005 versi 1.5; T1059.007 versi 2.2); LOLBAS (sekitar 245 entri per 2026-10-18; Regsvr32, Rundll32, Mshta, Certutil); Sysmon v15.22 (halaman Microsoft Learn 2026-09-10); Microsoft Learn Deprecated features dan Resources for deprecated features (2026-09-23, VBScript sebagai FOD, WMIC dihapus); ASR rules reference (2026-09-09); DeviceProcessEvents (2026-08-07); Atomic Red Team (T1218.010, T1218.005, T1218.011, T1204.002, T1036.003, T1059.007); Red Canary Threat Detection Report 2026 (data 2025); Splunk Enterprise 10.6 (SPL)'
---

# Day 13: Hunting living-off-the-land dan abuse script (LOLBin, signed binary proxy, binary yang diganti nama, dan script host)

Cakupan: hunting penyalahgunaan binary bawaan Windows (LOLBin) dan interpreter script lewat parent-child, argumen, lokasi, nama asli binary, dan kelangkaan, dengan baseline sebagai pembeda dari pemakaian sah, plus cara membuktikan bahwa query hunt sanggup menangkap pola yang dicari.

## Ide inti

Penyerang yang memakai binary bawaan Windows tidak membawa file asing yang bisa dikenali dari hash atau tanda tangannya. `rundll32.exe`, `regsvr32.exe`, `mshta.exe`, `certutil.exe`, PowerShell, dan `wscript.exe` sah, bertanda tangan Microsoft, dan dipakai ribuan kali sehari oleh Windows dan aplikasi. Karena itu yang diburu bukan nama binary-nya, melainkan cara binary itu dipakai: siapa parent-nya, argumen dan target apa yang ia bawa, dari folder mana ia berjalan, apakah namanya cocok dengan nama asli yang tertanam di file, dan seberapa langka kombinasi itu di lingkungan sendiri. Baseline dan konteks (aset, pengguna, aplikasi sah yang sudah dikenal) yang memisahkan pemakaian sah dari penyalahgunaan. Dan karena hasil yang paling sering muncul adalah "tidak ditemukan", hunt LOLBin baru bisa dipercaya bila query-nya sudah dibuktikan menangkap pola itu lewat uji jinak di lab.

Dari NOC kamu sudah mengenal masalah yang sama. Router dan switch membawa tool diagnostik bawaan: `ping`, `traceroute`, `copy tftp:`, packet capture di shell perangkat. Engineer memakainya setiap hari, dan penyusup yang mendapat akses ke perangkat juga akan memakai tool yang sama, karena tool itu sudah ada dan tidak memicu apa pun. Engineer berpengalaman tidak curiga pada `copy tftp:` sebagai perintah; ia curiga pada `copy tftp:` ke server yang tidak dikenal, dari akun yang tidak biasa, pukul 02:00. Untuk binary yang dipindah atau diganti nama, padanannya adalah hostname dan serial number: hostname perangkat bisa diganti siapa saja, tetapi serial number di EEPROM tetap. Sysmon mencatat nama asli binary dari resource versinya (`OriginalFileName`), sehingga `cmd.exe` yang disalin dan diganti nama tetap bisa dikenali. Batas analoginya ada dua. Tool diagnostik router jarang dipakai ribuan kali sehari oleh proses otomatis, sedangkan LOLBin Windows dipanggil terus-menerus oleh sistem dan aplikasi, sehingga daftar hitam nama langsung membanjiri antrean. Dan `OriginalFileName` tidak sekuat serial number: nilainya bisa kosong untuk sebagian file dan bisa diubah, walaupun mengubahnya ikut mengubah hash file.

```
  eksekusi LOLBin / script host (Sysmon EID 1)
        |
        +-- parent tidak lazim?      Office, browser, script host, WmiPrvSE
        +-- argumen/target aneh?     URL, scrobj, javascript:, vbscript:, about:, folder user
        +-- lokasi atau nama salah?  OriginalFileName vs Image, di luar System32/SysWOW64
        +-- langka di lingkungan?    installutil, msbuild, cmstp di workstation non-developer
        +-- script dari folder user? wscript/cscript dari Downloads, Temp, ekstraksi arsip
        |
        v
   bandingkan dengan baseline + konteks (aset, pengguna, aplikasi sah yang dikenal)
        |
        v
   label: jinak terkonfirmasi | perlu investigasi | data tidak cukup
        |
        +--> uji positif di VM lab: apakah query menangkap pola itu? (bila tidak, perbaiki query)
        |
        v
   laporan hunt + volume per pola + usulan detection (pola bervolume rendah) + backlog
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan. SOC PT JAB memakai Splunk Enterprise 10.6 dengan Enterprise Security (ES). Sysmon terpasang di semua server Windows dan di workstation OU `Workstations-EDR`: 214 host (61 server dan 153 workstation), sekitar 40% workstation; 229 workstation lain belum punya Sysmon, tetapi sebagian besar workstation Jakarta dan Bandung punya Microsoft Defender for Endpoint (MDE). Sejak 1 Februari 2027, kamu (analyst L2) memegang Program hunt PT JAB setiap Selasa dan Kamis. Dua catatan lama menjadi latar Day ini. Pertama, `HUNT-2027-002` (Selasa 2027-02-02) sudah menguji LOLBin yang dipakai untuk mengunduh tahap kedua (T1105) dan hasilnya tidak terbukti; jalur LOLBin untuk mengeksekusi kode belum pernah diuji. Kedua, pelajaran `INC-2026-019`: lampiran email berupa arsip ZIP berisi file `.js`, pengguna membukanya langsung dari dalam arsip, dan `wscript.exe` menjalankan skrip itu dari folder ekstraksi sementara di profil pengguna; host ketiga yang terdampak, `JKT-WS-0412`, baru ditemukan belakangan. Minggu ini sebuah laporan tahunan vendor keamanan yang dibaca SOC juga kembali menempatkan PowerShell, Windows Command Shell, dan teknik yang dijalankan lewat binary bawaan di peringkat atas. Kamis 2027-03-11 pukul 08:10, Sari Kusuma, analyst L2 pemegang konten detection `JAB - ...` di ES, menulis di chat SOC:

> "Pagi. Laporan vendor minggu ini lagi-lagi bilang LOLBin dan script host paling sering dipakai. Aku mau mulai menulis detection untuk itu, tapi takut antrean L1 banjir, karena `rundll32` saja jalan ratusan ribu kali seminggu. Tolong bantu aku paham dulu. Kenapa binary yang ditandatangani Microsoft bisa jadi masalah, dan kenapa tidak cukup alert berdasarkan nama? Daftar binary mana yang layak diawasi, dan untuk apa disalahgunakan? Pola apa yang membedakan pemakaian jahat dari yang sah? Kalau penyerang menyalin `cmd.exe` lalu mengganti namanya, rule kita yang berbasis nama proses masih menangkap tidak? Soal `INC-2026-019`: kata tim IT, VBScript sudah mau dihapus Microsoft, jadi masalah `wscript` selesai sendiri, benar? Yang paling penting: pola mana yang layak jadi detection tanpa membanjiri antrean? Dan kalau hunt-mu tidak menemukan apa-apa, bagaimana aku tahu query-nya tidak buta?"

Pesan itu memuat tujuh pertanyaan:

1. Kenapa binary bertanda tangan Microsoft bisa menjadi masalah, dan kenapa alert berbasis nama tidak cukup?
2. Binary mana yang layak diawasi, untuk apa disalahgunakan, dan teknik ATT&CK mana yang terkait?
3. Pola apa yang membedakan penyalahgunaan dari pemakaian sah?
4. Apakah rule berbasis nama proses masih menangkap binary yang disalin dan diganti nama?
5. Apakah deprecation VBScript menutup pola `INC-2026-019`, dan bagaimana memburu script host yang disalahgunakan?
6. Pola LOLBin mana yang layak menjadi detection tanpa membanjiri antrean?
7. Bila hunt tidak menemukan apa-apa, bagaimana membuktikan query-nya tidak buta?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2 dan 1.3, pertanyaan 3 di bagian 1.4 dan 1.7, pertanyaan 4 di bagian 1.5 dan 2.5, pertanyaan 5 di bagian 1.6 dan 2.6, pertanyaan 6 di bagian 1.8 dan 2.9, dan pertanyaan 7 di bagian 1.8 dan 2.4. Bagian 2 menjalankan tiga hunt hari itu: `HUNT-2027-023` (Office memunculkan signed proxy binary), `HUNT-2027-024` (binary sah di lokasi salah atau diganti nama), dan `HUNT-2027-025` (`wscript`/`cscript` menjalankan skrip dari folder yang bisa ditulis pengguna), lalu ditutup dengan laporan dan jawaban untuk Sari.

**Kapan relevan:** hunt terencana atas eksekusi lewat binary dan interpreter bawaan; setelah menemukan eksekusi mencurigakan di hunt lain, untuk melihat apakah rantainya memakai binary sah; saat merancang detection perilaku untuk LOLBin dan perlu angka volume dari data sendiri; dan saat ada perubahan platform (VBScript, WMIC) yang mengubah apa yang normal di workstation.
**Kapan bukan jawaban:** saat host yang dipertanyakan tidak mengirim process creation sama sekali (yang tersisa hanya celah data, Day 04); saat pemakaian sah meniru penyalahgunaan dengan sangat dekat dan tidak ada konteks aset atau pengguna untuk membedakannya (perlu konfirmasi ke pemilik, bukan query yang lebih pintar); dan saat yang dibutuhkan adalah kontrol pencegahan (ASR rule atau application control), karena hunt hanya melihat, tidak memblok.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah yang sudah dijelaskan di Day sebelumnya (antara lain LOLBin, `ProcessGuid`, Ingress Tool Transfer, baseline, stacking, long tail, first-seen, normalisasi path) tidak diulang. Tabel ini memuat istilah baru yang dipakai Day ini; kolom kanan memetakannya ke pekerjaan NOC dan SOC.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Living off the land (LOTL) | Penyerang memakai binary, script, dan library yang sudah ada di sistem, bukan tool sendiri | Penyusup memakai tool diagnostik bawaan router, bukan membawa perangkat sendiri |
| LOLBAS | Proyek komunitas yang mendokumentasikan binary, script, dan library Windows yang bisa disalahgunakan, beserta fungsinya | Katalog perintah bawaan perangkat yang pernah dipakai penyusup, beserta cara mengenalinya |
| Signed binary proxy execution (T1218) | Kode penyerang dijalankan "atas nama" binary bertanda tangan Microsoft, sehingga kontrol yang mempercayai tanda tangan terlewati | Perintah berbahaya dikirim lewat skrip otomasi resmi NMS supaya terlihat seperti pekerjaan rutin |
| Scriptlet (`.sct`) dan `scrobj.dll` | File XML berisi skrip COM; `regsvr32.exe` bisa diminta memuatnya lewat `scrobj.dll` | Template konfigurasi yang dijalankan oleh tool provisioning resmi |
| HTA (HTML Application) | File `.hta` atau skrip inline yang dijalankan `mshta.exe` dengan hak penuh pengguna | Halaman web lokal yang bisa menjalankan perintah perangkat |
| Windows Script Host (WSH) | Mesin skrip Windows: `wscript.exe` (GUI) dan `cscript.exe` (konsol) menjalankan JScript (`.js`, `.jse`) dan VBScript (`.vbs`, `.vbe`), juga `.wsf` | Interpreter skrip bawaan perangkat yang bisa menjalankan file apa pun yang disodorkan |
| `OriginalFileName` | Field Sysmon EID 1 berisi nama asli binary dari resource versi file PE, terpisah dari path di `Image` | Serial number di EEPROM, bukan hostname yang bisa diganti |
| Masquerading (T1036.003, T1036.005) | Binary sah diganti nama, atau file diberi nama dan lokasi yang meniru program sah | Perangkat asing diberi hostname mirip perangkat produksi |
| Folder yang bisa ditulis pengguna | Folder tempat pengguna biasa bisa menulis file tanpa hak admin: profil pengguna (`Downloads`, `Desktop`, `AppData`, `Temp`), `C:\Users\Public`, `C:\Windows\Temp` | Direktori upload publik di server FTP |
| Uji positif | Menjalankan aktivitas uji yang jinak di lab untuk membuktikan query menangkap pola yang dicari | Membuat gangguan buatan di lab untuk memastikan alarm NMS benar-benar berbunyi |
| Atomic Red Team | Katalog test kecil per teknik ATT&CK, masing-masing dengan GUID, untuk uji deteksi | Skrip uji gangguan standar yang dipakai semua engineer |
| Feature on Demand (FOD) | Komponen Windows opsional yang bisa dipasang, dinyalakan, atau dimatikan terpisah dari OS | Modul lisensi opsional di perangkat jaringan |
| ASR rule | Attack surface reduction rule di Microsoft Defender: memblok atau mengaudit perilaku berisiko, misalnya Office memunculkan child process | Access-list pencegahan di perangkat, bukan alarm |
| Script Block Logging (EID 4104) | Log PowerShell berisi isi script block yang dijalankan, termasuk yang sudah di-decode | Log perintah lengkap di AAA accounting, bukan sekadar "user login" |

### 1.1 LOTL: kenapa binary bertanda tangan menjadi masalah

Pertanyaan pertama Sari lahir dari intuisi yang wajar: file bertanda tangan Microsoft semestinya aman. Masalahnya, tanda tangan menjawab "siapa pembuat file ini", bukan "untuk apa file ini sedang dipakai".

LOTL memakai alat yang sudah ada: binary bawaan Windows (LOLBin), utilitas developer yang ditandatangani (misalnya MSBuild), dan interpreter script. Kesulitan deteksinya ada tiga:

- Binary sah dan ditandatangani, sehingga allowlist berbasis tanda tangan tidak membantu.
- Dipakai setiap hari untuk tujuan normal, sehingga volumenya tinggi. Di `HUNT-2027-002` (Day 02 bagian 2.2), `rundll32.exe` tercatat 212.640 kali dalam 14 hari di semua 214 host ber-Sysmon PT JAB.
- Perbedaan jahat dan sah ada di cara pakai (argumen, parent, lokasi, konteks), bukan di binary.

Karena itu alert berbasis nama tidak cukup: alert "setiap `rundll32.exe`" berbunyi ratusan ribu kali, dan alert "setiap `rundll32.exe` dengan URL" berbunyi 57 kali dalam 14 hari untuk perilaku jinak yang sama (aplikasi membuka tautan). Hunting LOTL hampir selalu berbasis perilaku: parent-child tidak lazim, argumen tidak lazim, lokasi tidak lazim, nama tidak cocok, atau kelangkaan.

Data industri menunjukkan kenapa topik ini tidak bisa dilewati. Red Canary Threat Detection Report, yang menghitung teknik ATT&CK paling sering muncul di ancaman terkonfirmasi pelanggannya, menempatkan PowerShell (T1059.001) di peringkat 2 dan Windows Command Shell (T1059.003) di peringkat 3 untuk data 2025. Di sepuluh besar yang sama ada Ingress Tool Transfer (T1105, peringkat 5), WMI (T1047, peringkat 7), dan Obfuscated Files or Information (T1027, peringkat 10), semuanya teknik yang sering dijalankan lewat binary dan interpreter bawaan [S6]. Daftar itu bias ke basis pelanggan satu vendor, tetapi polanya konsisten dari tahun ke tahun: PowerShell selalu berada di empat besar sejak laporan pertama 2019.

### 1.2 LOLBAS: peta binary yang bisa disalahgunakan

Pertanyaan kedua Sari ("daftar binary mana") dijawab dengan katalog, bukan ingatan. Di `HUNT-2027-002`, daftar LOLBin dicocokkan dulu dengan LOLBAS sebelum Execute (Day 02 bagian 2.1); prinsip yang sama berlaku di sini.

LOLBAS (Living Off The Land Binaries, Scripts and Libraries) adalah proyek komunitas yang mendokumentasikan binary dan script bawaan Windows yang bisa disalahgunakan, beserta fungsi penyalahgunaannya dan contoh command line [S2]. Untuk hunting, LOLBAS berguna sebagai:

- Daftar binary yang layak diawasi (certutil, rundll32, regsvr32, mshta, msiexec, bitsadmin, installutil, msbuild, dan lainnya).
- Pemetaan fungsi: binary mana bisa mengunduh, mana bisa mengeksekusi kode, mana bisa melewati kontrol.
- Pola command line dan IOC perilaku yang menandakan penyalahgunaan, dipakai sebagai titik awal, bukan daftar deteksi final.

Per 2026-10-10 LOLBAS memuat 245 entri, dan hitungan di halaman indeks per 2026-10-18 masih sekitar 245 (binary, library, script, dan binary Microsoft lain) [S2]. Kategori fungsi yang dipakai di entri antara lain Execute (menjalankan kode), Download (mengambil file dari URL), Copy, ADS (membaca atau menulis alternate data stream), Encode/Decode, dan AWL Bypass (melewati application allowlisting seperti AppLocker) [S2]. Tabel berikut meringkas binary yang dipakai di Day ini; baca kolom kanan, karena itulah yang dicari di telemetri [S2][S14][S15][S16][S17].

| Binary | Fungsi menurut LOLBAS | Teknik ATT&CK | Yang menonjol di telemetri |
|---|---|---|---|
| `certutil.exe` | Download, Encode, Decode, ADS | T1105, T1140 | Argumen `-urlcache` atau `-decode`; koneksi keluar (EID 3) dari certutil; certutil membuat file baru |
| `bitsadmin.exe` | Download, Copy, Execute, ADS | T1105, T1218 | Argumen `/transfer` dengan URL; job BITS di log `Microsoft-Windows-Bits-Client` |
| `rundll32.exe` | Execute, ADS | T1218.011 | DLL dari lokasi user-writable, argumen `javascript:`, parent Office, koneksi keluar dari rundll32 |
| `regsvr32.exe` | Execute, AWL Bypass | T1218.010 | `/i:` dengan file `.sct` atau URL, plus `scrobj.dll`; koneksi keluar dari regsvr32 |
| `mshta.exe` | Execute, Download, ADS | T1218.005 | File `.hta`, URL, atau skrip inline (`javascript:`, `vbscript:`, `about:`); child shell atau PowerShell; koneksi keluar |
| `msiexec.exe` | Execute | T1218.007 | `/i` atau `/q` dengan URL atau MSI dari folder user |
| `installutil.exe` | Execute, AWL Bypass, Download | T1218.004 | Assembly .NET dari folder user; jarang di workstation non-developer |
| `msbuild.exe` | Execute, AWL Bypass | T1127.001 | File proyek dari folder user; parent bukan IDE atau build agent |
| `cmstp.exe` | Execute, AWL Bypass | T1218.003 | File `.inf` dari folder user; hampir tidak pernah dipakai user biasa |
| `regasm.exe`/`regsvcs.exe` | Execute, AWL Bypass | T1218.009 | Assembly .NET dari folder user |
| `odbcconf.exe` | Execute | T1218.008 | Argumen yang memuat DLL |

Detail dari halaman entri yang menopang hunt hari ini:

- `regsvr32.exe`, `rundll32.exe`, `mshta.exe`, dan `certutil.exe` semuanya ada di `C:\Windows\System32\` dan `C:\Windows\SysWOW64\`, dan semua fungsi yang tercantum cukup dengan hak pengguna biasa [S14][S15][S16][S17]. Lokasi resmi ini dipakai sebagai patokan "lokasi benar" di bagian 1.5.
- Fungsi Execute `regsvr32.exe` mencakup scriptlet lokal dan jarak jauh lewat `scrobj.dll`, serta kode di fungsi `DllRegisterServer` dan `DllUnRegisterServer` sebuah DLL [S14].
- `rundll32.exe` punya fungsi Execute untuk DLL lokal, DLL dari share SMB, JScript jarak jauh lewat komponen mshtml, dan payload COM; menjalankan DLL dari NTFS alternate data stream dipetakan ke T1564.004 [S15].
- `mshta.exe` bisa menjalankan HTA lokal atau jarak jauh dan skrip yang ditulis langsung di command line; varian ADS-nya menurut LOLBAS tidak bekerja di Windows 10 1903 ke atas [S16].

Kategori dan entri LOLBAS bisa bertambah; daftar di atas adalah titik awal untuk baseline, bukan daftar lengkap. Contoh command line di LOLBAS diperlakukan sebagai referensi perilaku, bukan sesuatu untuk dijalankan.

### 1.3 Teknik ATT&CK terkait

Usulan detection ke Sari selalu menyebut teknik ATT&CK, jadi pemetaannya perlu tepat. Tabel berikut memetakan pola Day ini ke teknik; perhatikan kolom taktik, karena ATT&CK v20 memakai nama taktik yang berbeda dari dokumentasi lama.

| Teknik | ID | Taktik (v20) | Contoh binary/pola |
|---|---|---|---|
| System Binary Proxy Execution | T1218 | Stealth (TA0005) | rundll32 (.011), regsvr32 (.010), mshta (.005), msiexec (.007), installutil (.004), cmstp (.003), regsvcs/regasm (.009), odbcconf (.008) |
| Trusted Developer Utilities Proxy Execution | T1127 | Stealth | MSBuild (.001) |
| Masquerading: Rename Legitimate Utilities | T1036.003 | Stealth | `cmd.exe` atau `rundll32.exe` disalin dan diganti nama |
| Masquerading: Match Legitimate Resource Name or Location | T1036.005 | Stealth | Binary diberi nama program sah atau ditaruh di folder yang dipercaya |
| Command and Scripting Interpreter | T1059 | Execution | PowerShell (.001), cmd (.003), Visual Basic termasuk VBScript (.005), JavaScript termasuk JScript (.007) |
| Ingress Tool Transfer | T1105 | Command and Control | certutil, bitsadmin (sudah diuji di `HUNT-2027-002`) |
| User Execution: Malicious File | T1204.002 | Execution | Pengguna membuka lampiran yang menjalankan macro atau skrip |

Catatan per teknik:

- **T1218 di v20** (versi 4.0, diubah 2026-05-12) punya 14 sub-teknik, dari .001 Compiled HTML File sampai .015 Electron Applications (tidak ada .006), untuk platform Windows, Linux, dan macOS. Detection strategy-nya, DET0081, memandang masalahnya sebagai proxy execution lewat binary bertanda tangan yang dipercaya [S1]. Sub-teknik ini penting karena binary tersebut "memproksi" eksekusi kode: mereka menjalankan kode atas nama penyerang dengan tanda tangan Microsoft, melewati kontrol yang mempercayai binary bertanda tangan.
- **Taktik TA0005** bernama Stealth di ATT&CK v20, dengan deskripsi penyerang berusaha menyembunyikan tindakannya dan tampak seperti perilaku normal [S13]. Dokumentasi, rule, dan laporan lama menyebut taktik dengan ID yang sama sebagai Defense Evasion; keduanya perlu dikenali saat membaca rule Sigma atau laporan vendor lama.
- **T1218.011 Rundll32** (versi 3.0, detection strategy DET0475) menyebut pemakaian `javascript:` yang memanggil `RunHTMLApplication` di mshtml, eksekusi file `.cpl` lewat `Control_RunDLL`, DLL sistem bertanda tangan seperti `zipfldr.dll` dan `ieframe.dll` sebagai perantara, pemanggilan fungsi lewat nomor ordinal, dan pelaku yang memakai salinan `rundll32.exe` yang diganti nama [S7]. Satu contoh prosedur menarik untuk hunting: Raspberry Robin menjalankan `rundll32` tanpa parameter command line sama sekali untuk menghubungi C2 [S7]. Command line kosong pun bisa menjadi sinyal bila dibandingkan dengan baseline.
- **T1036.003** (detection strategy DET0005) menyebut penyerang juga menyalin atau memindah utility ke direktori tidak standar dan mengganti namanya, untuk menghindari detection berbasis path; analitik Windows-nya mencari binary yang nama file di disk tidak cocok dengan metadata PE seperti `OriginalFilename` atau `InternalName` [S8].
- **T1036.005** (versi 3.0, diubah 2026-09-11, DET0347) mencakup menaruh executable di direktori yang dipercaya seperti `System32` atau memberinya nama program yang dipercaya; spasi di akhir nama file dipisah ke T1036.006 [S9].
- **T1059.005** menyebut VBScript sebagai bahasa skrip bawaan Windows, dan detection strategy DET0076 menekankan rantai perilaku: script host yang memunculkan PowerShell, membuat koneksi, atau menyuntik proses [S11]. **T1059.007** menyebut JScript dijalankan Windows Script Host (`wscript`/`cscript`) atau HTA, dan analitik DET0264 menyoroti `wscript.exe`, `cscript.exe`, atau `mshta.exe` yang dimunculkan Office, browser, atau berjalan dari path tidak lazim [S12]. **T1059.001** (versi 1.6, diubah 2026-09-18, DET0455) menyoroti PowerShell dengan encoded command, parent tidak lazim, atau modul yang dimuat secara mencurigakan [S10].

### 1.4 Pola hunting LOLBin

Pertanyaan ketiga Sari adalah inti Day ini. Untuk `INC-2026-019` dan untuk kampanye di laporan vendor, pembedanya selalu sama: konteks di sekitar eksekusi, bukan eksekusinya sendiri.

Hunting LOLBin berbasis perilaku, bukan nama:

1. **Parent-child tidak lazim.** LOLBin yang diluncurkan oleh Office, browser, script host, atau `WmiPrvSE.exe`. `regsvr32.exe` yang diluncurkan Word jauh lebih mencurigakan daripada oleh installer. Rantai sering punya satu perantara (Word memunculkan `cmd.exe`, lalu `cmd.exe` memunculkan `regsvr32.exe`), jadi hunt parent-child langsung perlu dilengkapi hunt argumen yang tidak bergantung parent.
2. **Argumen tidak lazim.** Pola command line yang jarang untuk binary itu: URL, path user-writable, flag yang menandakan eksekusi jarak jauh atau scriptlet, skrip inline. Command line yang terlalu pendek juga bisa tidak lazim (`rundll32.exe` tanpa argumen, bagian 1.3).
3. **Lokasi anak atau target tidak lazim.** LOLBin memuat DLL atau file dari `\Users\Public\`, `\AppData\`, `\Temp\`.
4. **Binary di lokasi salah atau diganti nama.** LOLBin yang dijalankan dari path selain `System32`/`SysWOW64`, atau yang `OriginalFileName`-nya tidak cocok dengan nama file (bagian 1.5).
5. **Frekuensi.** LOLBin tertentu yang jarang dipakai di lingkungan (misalnya `installutil`, `msbuild` di workstation non-developer).

Satu jebakan khusus: pola jinak yang dikecualikan harus dipersempit sampai argumennya. Di `HUNT-2027-002`, `rundll32.exe url.dll,FileProtocolHandler https://...` dari Outlook dan aplikasi chat dinilai jinak (Day 02 bagian 2.5). Fungsi yang sama juga bisa dipakai untuk menjalankan perintah lokal; Atomic Red Team punya test T1218.011 "Rundll32 execute command via FileProtocolHandler" yang melakukan persis itu [S24]. Pengecualian "semua `url.dll,FileProtocolHandler`" akan ikut membutakan varian berbahaya; pengecualian yang benar mensyaratkan argumennya URL `http`/`https` dan parent-nya aplikasi yang dikenal.

### 1.5 Binary di lokasi salah atau diganti nama: `OriginalFileName`

Pertanyaan keempat Sari punya jawaban pendek: rule yang hanya memakai nama di `Image` tidak menangkap `cmd.exe` yang disalin ke `C:\Users\Public\svc.exe`. `Image` mencatat path file, dan path itu sepenuhnya dikendalikan siapa pun yang menyalin file.

Sysmon EID 1 mencatat field `OriginalFileName`, yaitu nama asli yang tertanam di resource versi file PE [S5][S27]. Manifest skema Sysmon memuat field ini di EID 1 (process create) dan EID 7 (image loaded) [S28]. Nama file di disk boleh berubah; resource versinya ikut tersalin bersama file. Karena itu pasangan dua field ini menjawab dua pertanyaan:

- **Diganti nama (T1036.003):** nama file di `Image` tidak sama dengan `OriginalFileName`. Contoh: `Image` berakhiran `hdk-shell.exe`, `OriginalFileName` bernilai `Cmd.Exe`.
- **Lokasi salah (T1036.005 atau salinan sederhana):** namanya sama, tetapi path di luar lokasi resmi binary itu (`System32`, `SysWOW64`, atau folder .NET Framework untuk `installutil`, `regasm`, `regsvcs`, dan `msbuild` bawaan).

Hal yang perlu diingat saat memakai field ini:

- Nilai `OriginalFileName` mengikuti apa yang ditulis pembuat file, termasuk huruf besar-kecilnya (`RUNDLL32.EXE`, `CertUtil.exe`), dan tidak selalu sama persis dengan nama file. Karena itu pemetaan nama ke `OriginalFileName` sebaiknya diambil dari data sendiri, dari binary yang memang berjalan di lokasi resmi (bagian 2.5), bukan ditulis dari ingatan.
- Nilainya bisa kosong (Sysmon menulis `-`) untuk file yang tidak punya resource versi, misalnya banyak tool buatan sendiri. Kosong bukan bukti jahat; itu hanya berarti pemeriksaan ini tidak berlaku untuk file itu.
- Resource versi bisa diedit, tetapi mengedit file mengubah hash-nya, sehingga salinan binary sistem yang diubah tidak lagi cocok dengan hash Microsoft. Untuk konfirmasi, pivot ke hash di field `Hashes` dan bandingkan dengan salinan resmi.
- Binary sah juga sering ada di luar `System32`: `MSBuild.exe` milik Visual Studio Build Tools, salinan lama binary sistem yang dibawa installer aplikasi, atau folder servicing Windows. Lokasi resmi tambahan ditulis sebagai daftar sempit, bukan dengan melonggarkan pola path.

Pencegahannya ada di luar hunting. Microsoft Defender punya ASR rule "Block use of copied or impersonated system tools", yang memperlakukan executable di `%windir%\System32` dan `%windir%\SysWOW64` sebagai tool sistem dan memblok salinannya atau file bernama sama yang berjalan dari lokasi lain, walaupun file itu bertanda tangan Microsoft [S21]. Status ASR rule di tenant MDE PT JAB belum pernah ditinjau program hunt; cek ke pemilik konsol MDE sebelum menganggapnya aktif.

### 1.6 Pola hunting abuse script, dan arti deprecation VBScript

Pertanyaan kelima Sari menggabungkan dua hal: cara memburu interpreter yang disalahgunakan, dan anggapan bahwa masalah `wscript` akan hilang sendiri.

Interpreter (PowerShell, wscript, cscript, cmd) dipakai sah setiap hari, jadi hunt berfokus pada ciri penyalahgunaan:

1. **PowerShell:** script block panjang, encoding (`-enc`), unduh di memori (`DownloadString`, `IEX`), atau bypass. Rule yang umum sudah menangkap `-enc` di command line; hunt melihat isi yang sudah di-decode di 4104. Hunt 4104 PT JAB sudah dijalankan sebagai `HUNT-2027-016` (Day 10); Day ini memakai 4104 hanya untuk pivot rantai (bagian 2.7).
2. **wscript/cscript:** menjalankan skrip dari lokasi user-writable atau lampiran; parent Office atau unduhan. Pola `INC-2026-019` adalah contoh paling jelas: file `.js` dari arsip lampiran, dijalankan dari folder ekstraksi sementara di profil pengguna.
3. **cmd:** rantai perintah (`&`, `|`), obfuscation (caret, variabel), one-liner panjang.
4. **Obfuscation umum:** command line dengan entropi tinggi, banyak karakter escape, atau sangat panjang.

Kuncinya tetap konteks: PowerShell panjang dari admin yang mengelola server itu normal; dari parent Word tidak. Skrip login di share `NETLOGON` yang dijalankan `cscript.exe` di setiap workstation itu normal; skrip `.js` dari folder `Temp` hasil membuka arsip tidak.

Sekarang anggapan tim IT. Status resmi Microsoft per halaman yang diperbarui 2026-09-23:

- VBScript dinyatakan deprecated pada Oktober 2023. Di rilis Windows berikutnya ia tersedia sebagai feature on demand sebelum dihapus dari OS; awalnya FOD itu dipasang sejak awal supaya pemakaian tidak terganggu selama migrasi [S18][S19].
- Blog developer Microsoft 365 (9 September 2025) merinci tiga fase: fase 1, VBScript tetap aktif secara default sebagai FOD; fase 2, sekitar 2026 atau 2027, FOD VBScript dinonaktifkan secara default; fase 3, waktunya belum ditentukan, VBScript dihapus sepenuhnya dari rilis Windows mendatang [S20]. Tanggal pasti fase 2 tidak disebut di sumber yang diperiksa; cek ulang halaman deprecated features Microsoft sebelum menulis tanggal di dokumen formal.
- Sumber resmi itu hanya membahas VBScript. JScript (`.js`, `.jse`) yang dijalankan `wscript.exe` tidak disebut sebagai bagian dari deprecation [S18][S19][S20].

Kesimpulan untuk Sari: deprecation VBScript tidak menutup pola `INC-2026-019`, karena file yang dipakai adalah `.js`. Ia juga belum menutup `.vbs`, karena sampai fase 2 berlaku di workstation PT JAB, VBScript masih aktif secara default, dan admin bisa menyalakannya kembali. Yang ia berikan justru pekerjaan untuk IT: inventaris skrip `.vbs` yang masih dipakai (skrip login, tugas terjadwal) sebelum fase 2 mematikannya. Hunt `HUNT-2027-025` menghasilkan inventaris itu sebagai efek samping (bagian 2.6). Bila nanti VBScript sudah nonaktif di sebuah host, eksekusi `.vbs` yang berhasil di host itu menjadi sinyal bahwa seseorang menyalakannya kembali, dan itu layak ditanyakan.

### 1.7 Baseline dan konteks (wajib untuk LOTL)

Sari khawatir antrean banjir. Yang mencegahnya bukan ambang yang lebih ketat, melainkan baseline dan konteks.

Karena LOLBin dan interpreter sah, baseline (Day 05) dan konteks adalah segalanya:

- **Baseline per binary:** parent dan argumen normal tiap LOLBin di lingkunganmu. Di PT JAB, `rundll32.exe url.dll,FileProtocolHandler https://...` dari Outlook dan aplikasi chat adalah normal; `regsvr32.exe` yang mendaftarkan DLL add-in rapat dari `AppData` milik updater vendor adalah normal.
- **Konteks aset:** workstation developer wajar menjalankan msbuild; workstation finance tidak. Server manajemen tanpa GUI wajar memakai certutil untuk unduhan vendor (Day 02 bagian 2.5); workstation Customer Service tidak.
- **Konteks user:** admin wajar menjalankan PowerShell panjang; user biasa tidak.

Tanpa baseline, hunt LOTL menghasilkan ribuan FP. Dengan baseline, "regsvr32 dengan argumen scriptlet dari parent Word di workstation finance" menonjol tajam. Baseline parent-child PT JAB yang sudah ada (`jab_hunt_baseline_parentchild.csv` dan macro normalisasi `jab_norm_parentchild`, Day 05 bagian 2.4 dan 2.5) bisa dipakai untuk pertanyaan "apakah pasangan ini baru"; Day ini menambah dua hal yang tidak ada di baseline itu: argumen dan nama asli binary.

### 1.8 Dari hunt ke detection, dan membuktikan query tidak buta

Dua pertanyaan terakhir Sari saling terkait. Pola yang layak jadi detection adalah pola yang volumenya di data sendiri rendah setelah pengecualian sempit, dan query-nya terbukti menangkap contoh positif.

LOTL adalah tempat kaya untuk detection berbasis perilaku. Rule yang biasanya sudah ada: certutil dengan `-urlcache`, child process dari `WmiPrvSE.exe`, encoded PowerShell. Bila hunt menemukan pola LOLBin yang belum tertutup rule, itu handover ke backlog detection engineering. Karena LOLBin punya banyak varian pemakaian, cakupan dihitung per prosedur, bukan per teknik: satu rule certutil tidak menutup rundll32 atau mshta, padahal ketiganya bisa dipetakan ke tujuan yang sama.

Untuk memutuskan pola mana yang dikirim ke Sari, setiap pola diukur dengan tiga angka dari data hunt: volume mentah, volume setelah pengecualian sempit yang sudah dikonfirmasi, dan jumlah host. Pola dengan volume nol atau beberapa kejadian per bulan setelah pengecualian layak menjadi rule; pola dengan puluhan kejadian jinak per bulan tanpa pembeda yang jelas lebih cocok menjadi laporan berkala atau tidak diusulkan sama sekali (bagian 2.9). Bentuk usulan dan levelnya mengikuti format abstract deteksi yang dipakai sejak `HUNT-2027-002` (Day 02 bagian 2.7).

Masalah kedua adalah "tidak ditemukan". Hunt LOLBin paling sering berakhir tanpa temuan, dan hasil itu bisa berarti dua hal yang sangat berbeda: memang tidak ada, atau query-nya tidak akan pernah menemukannya. Cara membedakannya adalah uji positif: jalankan aktivitas uji yang jinak di VM lab dengan konfigurasi telemetri yang sama, lalu jalankan query yang sama atas data lab. Bila query tidak menangkap uji itu, perbaiki query dulu sebelum hasil "tidak ditemukan" ditulis. Katalog Atomic Red Team cocok untuk ini karena tiap test punya GUID, deskripsi jejak, dan banyak di antaranya hanya membuka `calc.exe` atau mencetak informasi lokal [S3][S4][S23]. Uji positif dilakukan di lab terisolasi, tidak pernah di host produksi.

## 2. Contoh dan langkah praktis: tiga hunt LOLBin dan script host di PT JAB

Bagian ini menjalankan tiga hunt yang menjawab pertanyaan Sari, membuktikan query utama di VM lab, lalu menyusun laporan dan jawaban. Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi; query ditulis untuk Splunk PT JAB, dan versi untuk lab pribadi ada di bagian 3.

Asumsi data untuk semua query Splunk di bagian ini: Sysmon dikirim universal forwarder dan diparsing Splunk Add-on for Sysmon ke `index=sysmon` dengan `sourcetype=XmlWinEventLog`; field `Image`, `OriginalFileName`, `CommandLine`, `CurrentDirectory`, `ParentImage`, `User`, `Hashes`, dan `ProcessGuid` terekstrak dengan nama aslinya dari XML Sysmon. Rentang semua hunt adalah Februari 2027 penuh, Senin 2027-02-01 00:00 sampai Senin 2027-03-01 00:00 WIB. Satu catatan cakupan berlaku untuk ketiganya: Sysmon di `JKT-WS-0532` diam sejak Selasa 2027-02-02 10:14 (temuan Day 04), jadi host itu hanya tercakup di awal bulan dan ditulis di luar cakupan untuk sisa rentang. Cek nama index, sourcetype, dan field di lingkunganmu sebelum menjalankan.

### 2.1 Tiga abstract hari Kamis

Ketiga abstract ditulis Kamis 2027-03-11 pukul 08:40 sampai 09:20, setelah pesan Sari, dan disimpan di `jab-hunt/backlog/BACKLOG.md`. Pemicunya disebut eksplisit supaya pembaca laporan tahu kenapa hunt ini didahulukan: intel publik generik, celah yang ditinggalkan `HUNT-2027-002` (eksekusi, bukan unduhan), dan pelajaran `INC-2026-019`.

```
ID             : HUNT-2027-023
Dibuat         : 2027-03-11 (Kamis) 08:40, pemilik: <kamu>, reviewer: Dimas Prasetyo
Trigger        : Intel publik (laporan tahunan vendor: proxy execution lewat binary bawaan masih umum)
                 + celah HUNT-2027-002 (yang diuji baru fungsi unduh, bukan fungsi eksekusi)
Tipe (PEAK)    : Hypothesis-driven
Hipotesis      : Di host ber-Sysmon PT JAB ada aplikasi Office yang memunculkan regsvr32, rundll32,
                 atau mshta untuk menjalankan kode (langsung, atau lewat argumen scriptlet/inline/URL),
                 tanpa memicu alert apa pun.
ATT&CK         : T1218.010, T1218.011, T1218.005 (Stealth); prasyarat T1204.002
Data           : Sysmon EID 1, index=sysmon, 214 host ber-Sysmon, 2027-02-01 00:00 - 2027-03-01 00:00 WIB
Di luar cakupan: 229 workstation tanpa Sysmon; JKT-WS-0532 setelah 2027-02-02 10:14; rantai dengan
                 lebih dari satu perantara bila argumennya tidak tertangkap tahap B
Teknik analisis: Tahap A parent-child (Office -> proxy binary); tahap B pola argumen untuk semua parent;
                 uji positif di VM lab sebelum hasil ditulis
Kriteria sukses: Semua eksekusi tahap A dan tahap B dilabeli; query terbukti menangkap uji positif di lab
Handover       : IR (Dimas) bila terbukti; Sari (bahan usulan detection, diproses di Day 14)

ID             : HUNT-2027-024
Dibuat         : 2027-03-11 (Kamis) 09:00
Trigger        : Celah metode HUNT-2027-002 ("LOLBin yang diganti nama" di luar cakupan)
Tipe (PEAK)    : Baseline (pemetaan nama ke OriginalFileName dari data sendiri), lalu hypothesis-driven
Hipotesis      : Ada salinan binary sistem (LOLBin atau interpreter) yang berjalan dengan nama lain
                 atau dari luar lokasi resminya.
ATT&CK         : T1036.003, T1036.005 (Stealth)
Data           : Sysmon EID 1 (Image, OriginalFileName, Hashes), rentang dan host sama dengan -023;
                 pelengkap MDE DeviceProcessEvents untuk workstation tanpa Sysmon (retensi 30 hari)
Di luar cakupan: File tanpa resource versi (OriginalFileName kosong); POP Surabaya/Medan tanpa MDE
Kriteria sukses: Semua kombinasi OriginalFileName + nama + lokasi di luar pola resmi dilabeli

ID             : HUNT-2027-025
Dibuat         : 2027-03-11 (Kamis) 09:20
Trigger        : Pelajaran INC-2026-019 (.js dari arsip lampiran dijalankan wscript.exe dari folder
                 ekstraksi sementara) + pertanyaan Sari soal deprecation VBScript
Tipe (PEAK)    : Hypothesis-driven
Hipotesis      : Ada wscript.exe atau cscript.exe yang menjalankan skrip (.js/.jse/.vbs/.vbe/.wsf)
                 dari folder yang bisa ditulis pengguna (Downloads, Temp, folder ekstraksi arsip,
                 AppData, Desktop, Public) di host ber-Sysmon, tanpa alert.
ATT&CK         : T1059.007, T1059.005 (Execution); T1204.002
Data           : Sysmon EID 1, rentang dan host sama dengan -023
Di luar cakupan: 229 workstation tanpa Sysmon; skrip yang dijalankan lewat mshta atau rundll32
                 (sudah di -023); path relatif yang tidak bisa diselesaikan dari CurrentDirectory
Kriteria sukses: Semua lokasi skrip di luar share NETLOGON dan folder skrip server dilabeli;
                 inventaris skrip VBScript yang masih dipakai tersusun untuk IT
```

**Kapan gagal:** tiga hunt dijadikan satu abstract besar "hunting LOLBin". Kriteria sukses menjadi kabur, dan hasilnya tidak bisa dinyatakan per hipotesis; satu bagian yang inkonklusif membuat seluruhnya terlihat inkonklusif.

### 2.2 `HUNT-2027-023` tahap A: Office memunculkan proxy binary

Query ini adalah langkah Execute pertama `HUNT-2027-023` dan jawaban langsung untuk pola "regsvr32 dari Word" di bagian 1.4.

**Tujuan:** menghitung semua eksekusi `regsvr32.exe`, `rundll32.exe`, dan `mshta.exe` yang parent-nya aplikasi Office di Februari 2027.

```
index=sysmon sourcetype=XmlWinEventLog EventCode=1
    earliest="02/01/2027:00:00:00" latest="03/01/2027:00:00:00"
    (Image="*\\regsvr32.exe" OR Image="*\\rundll32.exe" OR Image="*\\mshta.exe"
     OR OriginalFileName IN ("regsvr32.exe", "rundll32.exe", "mshta.exe"))
| eval parent=lower(ParentImage)
| where match(parent, "\\\\(winword|excel|powerpnt|outlook|onenote|msaccess|mspub|visio)\.exe$")
| eval pname=mvindex(split(parent, "\\"), -1)
| eval cname=lower(if(isnotnull(OriginalFileName) AND OriginalFileName!="-",
                      OriginalFileName, mvindex(split(Image, "\\"), -1)))
| stats count AS runs dc(host) AS hosts values(User) AS users BY pname cname
| sort runs
```

Tabel berikut menjelaskan tiap bagian; perhatikan baris filter `OriginalFileName`, karena itulah yang membuat tahap ini tidak buta terhadap rename.

| Bagian | Fungsi |
|---|---|
| `EventCode=1` dan rentang absolut | Process creation Februari 2027, supaya hunt bisa diulang dengan hasil sama |
| `Image="*\\regsvr32.exe" OR ...` | Tiga proxy binary yang jadi fokus hipotesis. Pencocokan nilai field di command `search` tidak peka huruf besar/kecil |
| `OR OriginalFileName IN (...)` | Ikut menangkap salinan yang diganti nama, karena nama asli dari resource versi tidak berubah (bagian 1.5) |
| `eval parent=lower(ParentImage)` | Menyamakan huruf, karena `match()` peka huruf |
| `match(parent, "\\\\(winword\|...)\.exe$")` | Parent berupa aplikasi Office. Di string SPL, `\\\\` menjadi regex `\\` yang cocok dengan satu backslash |
| `eval cname=...` | Nama child dari `OriginalFileName` bila ada, dari path bila tidak, supaya salinan berganti nama tergabung dengan aslinya |
| `stats ... BY pname cname` | Satu baris per pasangan parent dan child |

Keluaran ilustrasi:

```
pname         cname         runs  hosts  users
outlook.exe   rundll32.exe  76    42     (42 akun)
```

Tidak ada baris untuk Word, Excel, PowerPoint, OneNote, Access, Publisher, atau Visio, dan tidak ada `regsvr32.exe` maupun `mshta.exe` dengan parent Office. Satu-satunya pasangan, Outlook memunculkan `rundll32.exe`, ditinjau dengan memecah command line-nya menjadi pola:

```
index=sysmon sourcetype=XmlWinEventLog EventCode=1
    earliest="02/01/2027:00:00:00" latest="03/01/2027:00:00:00"
    ParentImage="*\\outlook.exe" (Image="*\\rundll32.exe" OR OriginalFileName="rundll32.exe")
| eval cmd=lower(CommandLine)
| eval pola=case(match(cmd, "url\.dll,\s*fileprotocolhandler\s+\"?https?://"), "fph_url",
                 match(cmd, "shell32\.dll,\s*openas_rundll\s"), "openas",
                 true(), "lainnya")
| stats count AS runs dc(host) AS hosts BY pola
```

| Bagian | Fungsi |
|---|---|
| `match(cmd, "url\.dll,\s*fileprotocolhandler\s+\"?https?://")` | FileProtocolHandler yang argumennya URL web. Bentuk ini jinak; bentuk dengan path lokal tidak masuk pola ini (bagian 1.4). `\"` di string SPL menjadi tanda kutip di regex |
| `match(cmd, "shell32\.dll,\s*openas_rundll\s")` | Dialog "Open with" Windows, muncul saat lampiran berekstensi tidak dikenal dibuka |
| `true(), "lainnya"` | Semua yang tidak cocok dua pola di atas; ini baris yang harus kosong atau ditinjau satu per satu |

Keluaran ilustrasi:

```
pola       runs  hosts
fph_url    71    39
openas     5     5
lainnya    0     0
```

**Cara membaca hasil:** 76 eksekusi di 42 host (dua host muncul di kedua pola). Semua 71 `fph_url` membuka tautan `https://` dari email ke browser default, pola yang sama dengan yang dinilai jinak di `HUNT-2027-002` (Day 02 bagian 2.5). Lima `openas` membuka lampiran gambar teknik `.dwg` dari folder sementara Outlook (`...\INetCache\Content.Outlook\<rnd>\`) di lima workstation tim engineering; pengguna mengonfirmasi bahwa mereka mencoba membuka file itu dan memilih aplikasi dari dialog. Tidak ada eksekusi di pola `lainnya`. Untuk hipotesis tahap A: tidak ada aplikasi Office yang memunculkan proxy binary untuk menjalankan kode.

**Variasi:** versi data model untuk search head ES yang punya data model Endpoint terakselerasi, berguna bila volume EID 1 terlalu besar untuk raw search:

```
| tstats `security_content_summariesonly` count dc(Processes.dest) AS hosts
    FROM datamodel=Endpoint.Processes
    WHERE Processes.process_name IN (rundll32.exe, regsvr32.exe, mshta.exe, msiexec.exe, installutil.exe)
        earliest="02/01/2027:00:00:00" latest="03/01/2027:00:00:00"
    BY Processes.parent_process_name Processes.process_name
| `drop_dm_object_name(Processes)`
| search NOT parent_process_name IN (explorer.exe, services.exe, svchost.exe, msiexec.exe)
| sort count
```

Versi ini melakukan stacking LOLBin per parent untuk semua parent, lalu membuang parent yang umum sah; daftar parent sah disesuaikan dengan baseline. Macro `security_content_summariesonly` dan `drop_dm_object_name` berasal dari konten keamanan Splunk (ES Content Update); cek apakah keduanya dan data model Endpoint tersedia dan terakselerasi di search head yang kamu pakai. Pembandingnya: rule child `WmiPrvSE.exe` hanya menutup satu parent, sedangkan versi ini melihat semua parent tidak lazim.

**Kapan gagal:** rantai punya perantara (Word memunculkan `cmd.exe`, lalu `cmd.exe` memunculkan `regsvr32.exe`), sehingga parent langsung proxy binary bukan Office; daftar parent tidak memuat aplikasi Office lain yang dipakai di lingkunganmu; atau `ParentImage` kosong di sebagian event. Kasus pertama yang paling penting, dan itulah alasan tahap B ada.

### 2.3 `HUNT-2027-023` tahap B: argumen dan target untuk semua parent

Tahap ini menutup celah perantara di tahap A: proxy binary dengan argumen yang menandakan penyalahgunaan, apa pun parent-nya.

**Tujuan:** menandai `rundll32.exe`, `regsvr32.exe`, dan `mshta.exe` yang membawa URL, path user-writable, scriptlet, skrip inline, atau file HTA, lalu mengelompokkannya per pola.

```
index=sysmon sourcetype=XmlWinEventLog EventCode=1
    earliest="02/01/2027:00:00:00" latest="03/01/2027:00:00:00"
    (Image="*\\rundll32.exe" OR Image="*\\regsvr32.exe" OR Image="*\\mshta.exe")
    (CommandLine="*http://*" OR CommandLine="*https://*"
     OR CommandLine="*\\Users\\Public\\*" OR CommandLine="*\\AppData\\*" OR CommandLine="*\\Temp\\*"
     OR CommandLine="*scrobj*" OR CommandLine="*javascript:*" OR CommandLine="*vbscript:*" OR CommandLine="*.hta*")
| eval img=lower(mvindex(split(Image, "\\"), -1)), cmd=lower(CommandLine)
| eval pola=case(match(cmd, "scrobj|javascript:|vbscript:"), "scriptlet/inline",
                 match(cmd, "https?://"), "url",
                 match(cmd, "\.hta"), "hta",
                 match(cmd, "\\\\users\\\\public\\\\|\\\\appdata\\\\|\\\\temp\\\\"), "folder user",
                 true(), "lain")
| stats count AS runs dc(host) AS hosts values(ParentImage) AS parents BY img pola
| sort runs
```

| Bagian | Fungsi |
|---|---|
| Filter `CommandLine="*http://*" OR ...` | Argumen yang menandakan penyalahgunaan: URL, lokasi user-writable, scriptlet (`scrobj`), skrip inline `javascript:`/`vbscript:`, file HTA. Pola ini diturunkan dari fungsi LOLBAS [S2] |
| `eval pola=case(...)` | Satu label per eksekusi, dengan urutan prioritas: scriptlet/inline dulu, karena itu yang paling jarang sah |
| `"\\\\users\\\\public\\\\\|..."` | Di string SPL menjadi regex `\\users\\public\\`, cocok dengan `\users\public\` |
| `values(ParentImage)` | Konteks parent untuk triage |
| `stats ... BY img pola` | Satu baris per binary dan pola, bukan per command line unik, supaya bisa dibaca |

Keluaran ilustrasi:

```
img           pola               runs  hosts  parents
mshta.exe     hta                3     3      setup.exe
rundll32.exe  folder user        5     5      OUTLOOK.EXE
regsvr32.exe  folder user        14    6      vidmeetupdate.exe
rundll32.exe  url                118   52     OUTLOOK.EXE, (aplikasi chat kantor)
regsvr32.exe  scriptlet/inline   0
rundll32.exe  scriptlet/inline   0
mshta.exe     scriptlet/inline   0
```

**Cara membaca hasil:** 140 eksekusi bertanda (3 + 5 + 14 + 118), semuanya masuk empat kelompok yang dikenal:

- **`rundll32.exe` dengan URL (118 di 52 host):** 71 dari Outlook (sama dengan tahap A) dan 47 dari aplikasi chat kantor, semuanya `url.dll,FileProtocolHandler https://...`. Jinak, pola sama dengan `HUNT-2027-002`.
- **`rundll32.exe` folder user (5):** lima `OpenAs_RunDLL` dari tahap A. Jinak.
- **`regsvr32.exe` folder user (14 di 6 host):** `regsvr32.exe /s` mendaftarkan DLL add-in Outlook dari aplikasi rapat video di `C:\Users\<user>\AppData\Local\VidMeet\Addin\`, parent updater vendor `vidmeetupdate.exe`. Pivot ke `Hashes` dan halaman file di MDE: DLL bertanda tangan vendor, hash sama di keenam host, dan waktu eksekusi cocok dengan jadwal pembaruan vendor. Jinak.
- **`mshta.exe` HTA (3 di 3 host):** HTA lokal dari folder installer driver printer, parent `setup.exe`, sama dengan pola Januari di `HUNT-2027-002`. Jinak.

Tidak ada satu pun eksekusi scriptlet atau skrip inline. Untuk hipotesis `HUNT-2027-023` di 214 host ber-Sysmon selama Februari: tidak ditemukan. Hasil ini baru ditulis setelah uji positif di bagian 2.4, dan uji itu ternyata memaksa satu perbaikan pada pola tahap B.

**Variasi:** `rundll32.exe` tanpa argumen sama sekali, prosedur yang disebut ATT&CK untuk Raspberry Robin [S7]: `| where match(lower(CommandLine), "rundll32(\.exe)?\"?\s*$")` setelah base search `Image="*\\rundll32.exe"`. Bandingkan jumlahnya dengan baseline; di PT JAB pola ini perlu diukur dulu sebelum dianggap langka.

**Kapan gagal:** argumen diobfuscate (misalnya karakter escape atau variabel lingkungan yang baru diekspansi saat dijalankan) sehingga pola teks tidak cocok; skrip inline memakai skema lain yang tidak ada di daftar; atau pengecualian kelompok jinak ditulis terlalu lebar (bagian 1.4). Bagian 2.4 menunjukkan kasus kedua terjadi sungguhan.

### 2.4 Uji positif di VM lab: membuktikan query `HUNT-2027-023` tidak buta

Langkah ini menjawab pertanyaan ketujuh Sari. Hasil "tidak ditemukan" di bagian 2.2 dan 2.3 baru ditulis setelah query yang sama terbukti menangkap pola itu di lab.

**Tujuan:** menjalankan test Atomic Red Team yang jinak di VM lab, lalu menjalankan query tahap A dan tahap B atas data lab.

Lingkungan uji adalah VM `jab-lab-win11` di jaringan lab SOC yang terisolasi, dengan Microsoft Office terpasang, snapshot bersih, dan konfigurasi Sysmon yang disalin dari profil workstation `Workstations-EDR`. VM mengirim ke Splunk lab `jab-lab-splunk01`, terpisah dari `jkt-splunk-sh01`, ke index bernama sama (`sysmon`) supaya query bisa dipakai tanpa diubah selain rentang waktunya. Tidak ada test yang dijalankan di host PT JAB. Prasyarat test yang mengunduh file pendukung dari GitHub (misalnya scriptlet untuk T1218.010 test 1 [S3]) diambil dulu sebelum VM diputus dari internet.

Test yang dijalankan Kamis 2027-03-11 pukul 10:30 sampai 11:40 (jejak yang diharapkan diambil dari deskripsi test [S3][S4][S23]):

| Urutan | Test | Yang terjadi | Jejak yang diharapkan |
|---|---|---|---|
| 1 | T1204.002 test 3, Maldoc choice flags command execution, `0330a5d2-a45a-4272-a9ee-e364411c4b18` | Macro di dokumen Word memunculkan `cmd.exe` yang menjalankan perintah `choice` | EID 1 `cmd.exe` dengan parent `WINWORD.EXE`: bukti bahwa parent Office tercatat dan terekstrak |
| 2 | Variasi test 3: salinan lokal test itu, dengan perintah `choice` diganti perintah T1218.010 test 1 (scriptlet lokal) | Macro memunculkan `regsvr32.exe` dengan `/i:` berisi path `.sct` dan `scrobj.dll`; scriptlet membuka `calc.exe` | EID 1 `regsvr32.exe` dengan parent `WINWORD.EXE`; EID 1 `calc.exe` dengan parent `regsvr32.exe` |
| 3 | T1218.010 test 1, Regsvr32 local COM scriptlet execution, `449aa403-6aba-47ce-8a37-247d21ef0306` | Sama dengan urutan 2, tetapi dijalankan dari PowerShell | EID 1 `regsvr32.exe` dengan `scrobj` di command line, parent `powershell.exe` |
| 4 | T1218.005 test 2, Mshta executes VBScript to execute malicious command, `906865c3-e05f-4acc-85c4-fbc185455095` | `mshta.exe` menjalankan VBScript inline yang membuka PowerShell, lalu PowerShell menjalankan skrip lokal yang menampilkan info user | EID 1 `mshta.exe` dengan `vbscript:`; EID 1 `powershell.exe` dengan parent `mshta.exe`; 4104 berisi isi skrip lokal |
| 5 | T1218.005 test 10, Mshta used to Execute PowerShell, `8707a805-2b76-4f32-b1c0-14e558205772` | `mshta.exe` menjalankan HTA inline berskema `about:` yang membuka PowerShell, mencetak pesan, lalu jeda | EID 1 `mshta.exe` dengan `about:` di command line; EID 1 `powershell.exe` dengan parent `mshta.exe` |

Urutan 2 bukan test katalog yang berdiri sendiri, melainkan gabungan dua test katalog: harness dokumen Office dari test 3 dan perintah regsvr32 dari T1218.010 test 1. Gabungan ini perlu karena tidak ada test T1204.002 di katalog yang langsung membuat Office memunculkan proxy binary [S23]; isinya tetap hanya membuka `calc.exe`.

Hasil query atas data lab (keluaran ilustrasi):

```
Tahap A (Office -> proxy binary):
pname         cname          runs  hosts
winword.exe   regsvr32.exe   1     1        <- urutan 2 tertangkap

Tahap B (pola argumen, semua parent):
img           pola               runs  hosts  parents
regsvr32.exe  scriptlet/inline   2     1      WINWORD.EXE, powershell.exe   <- urutan 2 dan 3
mshta.exe     scriptlet/inline   1     1      powershell.exe                <- urutan 4
(urutan 5 tidak muncul)
```

**Cara membaca hasil:** tahap A menangkap rantai Word ke `regsvr32.exe`, dan tahap B menangkap scriptlet dan VBScript inline. Urutan 5 lolos dari tahap B: command line `mshta.exe` berisi `about:` dan tidak memuat `javascript:`, `vbscript:`, `.hta`, URL, atau path folder user. Tanpa uji ini, hasil "tidak ditemukan" untuk mshta akan ditulis untuk query yang buta terhadap satu bentuk skrip inline. Perbaikannya ada dua:

- Tambah `about:` ke pola scriptlet/inline (`match(cmd, "scrobj|javascript:|vbscript:|about:")`) dan ke filter base search (`OR CommandLine="*about:*"`).
- Untuk `mshta.exe` khususnya, balik logikanya: tandai semua eksekusi yang argumennya bukan path file `.hta` lokal, karena di PT JAB `mshta.exe` hanya muncul 3 kali sebulan dan semuanya HTA lokal installer.

Query tahap B yang sudah diperbaiki dijalankan ulang atas data lab (urutan 5 kini tertangkap) dan atas data PT JAB Februari: hasilnya tetap 140 eksekusi di empat kelompok jinak yang sama, tanpa tambahan. VM dikembalikan ke snapshot bersih pukul 11:45.

**Variasi:** ulangi urutan 2 dengan `rundll32.exe` sebagai child (misalnya perintah dari T1218.011 test 2, yang menjalankan perintah lewat VBScript tanpa unduhan [S24]) untuk memastikan cabang `rundll32` juga tertangkap. Simpan GUID, jam, dan hasil query tiap test di `jab-hunt/hunts/HUNT-2027-023/` sebagai bukti uji.

**Kapan gagal:** konfigurasi Sysmon VM lab berbeda dari produksi (misalnya tanpa field `OriginalFileName` atau dengan filter yang membuang `rundll32.exe`), sehingga uji lulus di lab tetapi query tetap buta di produksi; Defender di VM memblok test sebelum proses tercatat; atau test dijalankan tanpa mencatat jam, sehingga hasil tidak bisa dicocokkan dengan event.

### 2.5 `HUNT-2027-024`: `OriginalFileName` lawan `Image`

Hunt ini menjawab pertanyaan keempat Sari dengan data: apakah ada salinan binary sistem yang berjalan dengan nama lain atau dari lokasi lain. Pendekatannya dua langkah, sesuai bagian 1.5: ambil dulu pemetaan nama ke `OriginalFileName` dari data sendiri, lalu cari yang menyimpang.

**Tujuan langkah 1:** membangun lookup `jab_hunt_sysbin_ofn.csv` berisi nilai `OriginalFileName` dari 16 LOLBin dan interpreter yang berjalan di lokasi resminya.

```
index=sysmon sourcetype=XmlWinEventLog EventCode=1
    earliest="02/01/2027:00:00:00" latest="03/01/2027:00:00:00"
| eval p=replace(lower(Image), "\\\\", "/"), name=mvindex(split(p, "/"), -1), ofn=lower(OriginalFileName)
| where in(name, "certutil.exe", "bitsadmin.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe",
        "msiexec.exe", "cmstp.exe", "odbcconf.exe", "installutil.exe", "msbuild.exe", "regasm.exe",
        "regsvcs.exe", "wscript.exe", "cscript.exe", "cmd.exe", "powershell.exe")
    AND match(p, "^c:/windows/(system32|syswow64|microsoft\.net/framework(64)?/v[0-9.]+)/[^/]+$")
    AND isnotnull(ofn) AND ofn!="-"
| stats count AS runs dc(host) AS hosts BY ofn name
| outputlookup override_if_empty=false jab_hunt_sysbin_ofn.csv
```

| Bagian | Fungsi |
|---|---|
| `replace(lower(Image), "\\\\", "/")` | Huruf kecil dan backslash menjadi `/`, sama dengan aturan macro normalisasi Day 05 bagian 2.4; regex berikutnya tidak perlu escape backslash |
| `where in(name, ...)` | Daftar pantauan: 11 binary dari tabel bagian 1.2, empat interpreter, dan `bitsadmin.exe`. `in()` dipakai di `where` supaya tidak bergantung versi |
| `match(p, "^c:/windows/(system32\|syswow64\|microsoft\.net/framework(64)?/v[0-9.]+)/[^/]+$")` | Lokasi resmi: langsung di `System32`, `SysWOW64`, atau folder versi .NET Framework (untuk `installutil`, `msbuild`, `regasm`, `regsvcs`) |
| `ofn!="-"` | Buang event tanpa resource versi |
| `stats ... BY ofn name` | Satu baris per pasangan nilai asli dan nama, dari data sendiri |
| `override_if_empty=false` | Bila search gagal dan hasilnya kosong, lookup lama tidak terhapus |

Keluaran ilustrasi (ringkas): 16 baris tertulis ke lookup, satu per binary, misalnya `rundll32.exe` dengan nama `rundll32.exe`, `cmd.exe` dengan nama `cmd.exe`, `certutil.exe` dengan nama `certutil.exe`. Setelah `lower()`, sebagian besar nilai sama dengan nama file; bila ada yang tidak sama (misalnya akhiran tambahan di nilai asli), justru itulah alasan pemetaan diambil dari data, bukan ditulis tangan. Cek baris-baris itu di lab-mu sebelum mempercayai daftar orang lain.

**Tujuan langkah 2:** mencari eksekusi yang `OriginalFileName`-nya ada di lookup tetapi nama atau lokasinya menyimpang.

```
index=sysmon sourcetype=XmlWinEventLog EventCode=1
    earliest="02/01/2027:00:00:00" latest="03/01/2027:00:00:00"
    OriginalFileName=* NOT OriginalFileName="-"
| eval p=replace(lower(Image), "\\\\", "/"), name=mvindex(split(p, "/"), -1), ofn=lower(OriginalFileName)
| lookup jab_hunt_sysbin_ofn.csv ofn OUTPUT name AS expected_name
| where isnotnull(expected_name)
    AND (name!=expected_name
         OR NOT match(p, "^c:/windows/(system32|syswow64|microsoft\.net/framework(64)?/v[0-9.]+)/[^/]+$"))
| eval loc=replace(p, "^c:/users/[^/]+/", "c:/users/<user>/")
| stats count AS runs dc(host) AS hosts values(host) AS host_list values(User) AS users
        values(ParentImage) AS parents values(Hashes) AS hashes BY ofn name loc
| sort runs
```

| Bagian | Fungsi |
|---|---|
| `OriginalFileName=* NOT OriginalFileName="-"` | Hanya event yang punya nama asli |
| `lookup ... OUTPUT name AS expected_name` | Nama resmi untuk nilai asli itu. Kedua sisi sudah di-`lower()`, jadi pencocokan lookup yang peka huruf tidak jadi masalah |
| `name!=expected_name` | Diganti nama (T1036.003) |
| `NOT match(p, ...)` | Lokasi di luar pola resmi (T1036.005 atau salinan sederhana) |
| `eval loc=replace(...)` | Profil pengguna dinormalisasi menjadi `<user>`, supaya salinan yang sama di banyak profil tergabung |
| `values(Hashes)` | Untuk konfirmasi: apakah salinan itu identik dengan binary Microsoft |

Keluaran ilustrasi:

```
ofn           name           loc                                                                    runs  hosts
cmd.exe       hdk-shell.exe  c:/users/<user>/hdkit/bin/hdk-shell.exe                                9     1
regsvr32.exe  regsvr32.exe   c:/program files (x86)/payrollclient/bin/regsvr32.exe                  76    4
msbuild.exe   msbuild.exe    c:/program files/microsoft visual studio/2022/buildtools/msbuild/
                             current/bin/amd64/msbuild.exe                                          212   3
```

**Cara membaca hasil:** 297 eksekusi di 8 host, tiga kelompok:

- **`hdk-shell.exe` = `cmd.exe` yang diganti nama (9 eksekusi, `JKT-WS-0618`, `fikri.hasan`):** satu-satunya kasus rename. Parent-nya `hdkit.exe`, menu toolkit portabel tim IT End User Computing yang disimpan di profil pengguna. Hash `hdk-shell.exe` identik dengan `cmd.exe` Windows di host itu. Fikri dan atasannya mengonfirmasi: toolkit lama itu dibuat mantan staf, dan salinan `cmd.exe` diganti nama supaya menu bisa membuka konsol dengan profil warna sendiri. Label: jinak terkonfirmasi. Catatan: perilaku ini persis yang akan diblok ASR rule "Block use of copied or impersonated system tools" [S21], dan persis yang dilakukan penyerang yang menghindari rule berbasis nama. Rekomendasi ke tim IT: ganti salinan itu dengan pintasan ke `cmd.exe` asli.
- **`regsvr32.exe` salinan di folder PayrollClient (76 eksekusi di 4 workstation HR Jakarta):** nama sama, lokasi salah. Launcher aplikasi payroll menjalankan salinan `regsvr32.exe /s` untuk mendaftarkan kontrol laporan setiap kali aplikasi dibuka. Hash salinan itu cocok dengan versi lama `regsvr32.exe` bertanda tangan Microsoft yang dibawa installer vendor; pola yang sama ada di data Januari. Label: jinak terkonfirmasi, dengan usulan ke IT dan vendor agar launcher memakai `regsvr32.exe` sistem.
- **`MSBuild.exe` Visual Studio Build Tools (212 eksekusi di 3 workstation tim DevOps):** binary sah dengan nama asli sama, di lokasi produk resmi Visual Studio, bukan salinan. Label: jinak. Path ini ditambahkan ke daftar lokasi resmi tambahan, sebagai daftar sempit per path produk, bukan dengan melonggarkan pola `c:/program files/`.

Validasi hipotesis: tidak terbukti. Ada satu rename dan satu salinan di lokasi salah, keduanya sah dan dikonfirmasi pemiliknya.

**Variasi 1, workstation tanpa Sysmon lewat MDE.** Sebagian besar dari 229 workstation tanpa Sysmon punya MDE, dan tabel `DeviceProcessEvents` di advanced hunting memuat `ProcessVersionInfoOriginalFileName`, `FileName`, dan `FolderPath` untuk proses yang dibuat [S22]. Retensi advanced hunting MDE 30 hari, jadi saat dijalankan Kamis 2027-03-11, data Februari yang tersisa hanya sekitar 9 sampai 28 Februari.

```
DeviceProcessEvents
| where Timestamp between (datetime(2027-02-09 00:00:00) .. datetime(2027-03-01 00:00:00))
| where ProcessVersionInfoOriginalFileName in~ ("certutil.exe", "rundll32.exe", "regsvr32.exe",
        "mshta.exe", "cmd.exe", "wscript.exe", "cscript.exe", "bitsadmin.exe")
| where not(FolderPath startswith @"C:\Windows\System32" or FolderPath startswith @"C:\Windows\SysWOW64")
        or not(FileName =~ ProcessVersionInfoOriginalFileName)
| summarize runs=count(), hosts=dcount(DeviceName) by ProcessVersionInfoOriginalFileName, FileName, FolderPath
| order by runs asc
```

`in~` dan `=~` tidak peka huruf besar/kecil, sehingga perbedaan penulisan nilai asli tidak jadi masalah. `datetime()` di advanced hunting ditulis dalam UTC; batas di atas sengaja dibulatkan ke hari, dan selisih tujuh jam dengan WIB dicatat di laporan. `startswith` tanpa backslash penutup dipakai karena kolom `FolderPath` dideskripsikan sebagai folder berisi file; cek isinya di tenant-mu, dan sadari bahwa pola ini juga akan menerima folder seperti `System32xyz`. Keluaran ilustrasi: 27 eksekusi salinan `regsvr32.exe` PayrollClient di 2 workstation HR tanpa Sysmon, tidak ada yang lain. Cakupan tetap bolong untuk 23 workstation POP Surabaya dan Medan yang tanpa MDE maupun Sysmon.

**Variasi 2, LOLBin langka per host.** Stacking LOLBin yang jarang dipakai di workstation biasa (utilitas developer dan konfigurasi), memakai data model Endpoint:

```
| tstats `security_content_summariesonly` count dc(Processes.dest) AS hosts
    FROM datamodel=Endpoint.Processes
    WHERE Processes.process_name IN (installutil.exe, msbuild.exe, regasm.exe, regsvcs.exe, cmstp.exe, odbcconf.exe)
        earliest="02/01/2027:00:00:00" latest="03/01/2027:00:00:00"
    BY Processes.dest Processes.process_name Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| sort count
```

Kemunculan di workstation non-developer menonjol. Daftar ini dari kategori LOLBAS; sesuaikan dengan apa yang wajar di lingkunganmu. Di PT JAB, hasilnya akan memuat tiga workstation DevOps di atas; selain itu, kemunculan `cmstp.exe` atau `installutil.exe` di workstation mana pun langsung ditinjau.

**Kapan gagal:** file salinan tidak punya resource versi atau resource-nya diedit (pivot ke hash menjadi satu-satunya pegangan); lookup langkah 1 dibangun dari periode yang sudah tercemar, sehingga salinan yang diganti nama ikut dianggap resmi; atau daftar pantauan terlalu sempit. Satu kasus baru layak ditambahkan ke daftar: menurut Microsoft, WMIC sudah dihapus dan tidak lagi tersedia sebagai FOD di Windows 11 24H2 ke atas sejak pembaruan Agustus 2026 [S18], jadi `wmic.exe` yang berjalan di host versi itu adalah salinan dari luar dan layak ditinjau.

### 2.6 `HUNT-2027-025`: `wscript`/`cscript` dari folder yang bisa ditulis pengguna

Hunt ini menguji ulang pola `INC-2026-019` di seluruh host ber-Sysmon, dan sekaligus menyusun inventaris skrip VBScript yang dibutuhkan IT sebelum fase 2 deprecation (bagian 1.6).

**Tujuan:** mengelompokkan setiap eksekusi `wscript.exe` dan `cscript.exe` di Februari menurut lokasi skrip yang dijalankannya.

```
index=sysmon sourcetype=XmlWinEventLog EventCode=1
    earliest="02/01/2027:00:00:00" latest="03/01/2027:00:00:00"
    (Image="*\\wscript.exe" OR Image="*\\cscript.exe" OR OriginalFileName IN ("wscript.exe", "cscript.exe"))
| eval cmd=replace(lower(CommandLine), "\\\\", "/")
| eval args=replace(cmd, "^\"?[^\"]*?(wscript|cscript)(\.exe)?\"?\s*", "")
| rex field=args "(?<script>([a-z]:|//[a-z0-9.-]+)/[^\"]+?\.(js|jse|vbs|vbe|wsf|wsh)\b)"
| eval lokasi=case(isnull(script), "tanpa path absolut",
                   match(script, "^//"), "share jaringan",
                   match(script, "/appdata/local/temp/(temp\d+_|rar\$|7z)"), "ekstraksi arsip di temp",
                   match(script, "^c:/users/[^/]+/downloads/"), "downloads",
                   match(script, "/appdata/local/temp/|^c:/windows/temp/"), "temp",
                   match(script, "^c:/users/(public|[^/]+/(desktop|appdata))/"), "profil pengguna",
                   true(), "lokasi lain")
| eval ext=replace(script, "^.*\.", "")
| stats count AS runs dc(host) AS hosts values(ext) AS ext values(ParentImage) AS parents BY lokasi
| sort runs
```

Tabel berikut menjelaskan tiap bagian; baris `rex` dan `case` yang paling perlu diuji, karena di situ path skrip ditentukan.

| Bagian | Fungsi |
|---|---|
| Filter `Image` dan `OriginalFileName IN (...)` | Script host asli maupun salinannya |
| `eval cmd=replace(lower(CommandLine), "\\\\", "/")` | Huruf kecil, backslash menjadi `/`; share `\\corp.jab.example\NETLOGON\` menjadi `//corp.jab.example/netlogon/` |
| `eval args=replace(cmd, "^\"?[^\"]*?(wscript\|cscript)(\.exe)?\"?\s*", "")` | Buang path script host di awal command line, supaya regex berikutnya tidak mengira path `wscript.exe` sebagai bagian path skrip |
| `rex ... "(?<script>([a-z]:\|//[a-z0-9.-]+)/[^\"]+?\.(js\|...)\b)"` | Path skrip absolut (drive atau share). Syarat `//host/` membuat opsi `cscript` seperti `//nologo` dan `//b` tidak dikira share. `\b` mencegah `.json` terbaca sebagai `.js` |
| `case(...)` | Label lokasi, dengan pola ekstraksi arsip diperiksa sebelum `temp` biasa |
| `temp/(temp\d+_\|rar\$\|7z)` | Pola folder sementara saat file dibuka langsung dari arsip. Pola `Temp1_<nama zip>` adalah yang tercatat di `INC-2026-019`; dua lainnya pola yang umum dipakai pengelola arsip pihak ketiga. Cek pola persisnya di versi Windows dan software arsip lab-mu |
| `values(ext)` | Jenis skrip: `.js` dan `.jse` (JScript) dibedakan dari `.vbs` (VBScript) untuk inventaris |

Regex ini diuji dulu dengan kasus positif dan negatif sebelum dijalankan atas data Februari. Tabel berikut memperlihatkan hasil `script` dan `lokasi` untuk contoh command line; dua baris terakhir adalah kasus negatif yang tidak boleh salah label.

| Command line (setelah lower dan `/`) | `script` | `lokasi` |
|---|---|---|
| `"c:/windows/system32/wscript.exe" "c:/users/x/appdata/local/temp/temp1_faktur.zip/faktur.js"` | `c:/users/x/appdata/local/temp/temp1_faktur.zip/faktur.js` | ekstraksi arsip di temp |
| `c:/windows/system32/cscript.exe //nologo //b //corp.jab.example/netlogon/map-drives.vbs` | `//corp.jab.example/netlogon/map-drives.vbs` | share jaringan |
| `cscript.exe //nologo "c:/users/x/downloads/olt-diag-3.1/collect_logs.vbs"` | `c:/users/x/downloads/olt-diag-3.1/collect_logs.vbs` | downloads |
| `wscript.exe "c:/users/x/documents/config.json.vbs"` | `c:/users/x/documents/config.json.vbs` | lokasi lain |
| `cscript.exe //nologo prndrvr.vbs -a` | (kosong) | tanpa path absolut |

Baris keempat sengaja dibuat: berkat `\b`, path tidak terpotong di `.json`, dan file dengan ekstensi ganda tetap terbaca utuh. Folder `Documents` tidak ada di daftar folder user di `case()`, sehingga jatuh ke "lokasi lain"; itu pilihan sadar karena di PT JAB folder itu disinkronkan JAB DocSync, dan baris "lokasi lain" tetap ditinjau.

Keluaran ilustrasi:

```
lokasi                    runs   hosts  ext        parents
downloads                 2      1      vbs        cmd.exe
tanpa path absolut        18     7      vbs        setup.exe, msiexec.exe
profil pengguna           112    6      vbs        explorer.exe
lokasi lain               252    9      vbs        svchost.exe
share jaringan            3412   153    vbs        gpscript.exe
temp                      0
ekstraksi arsip di temp   0
```

**Cara membaca hasil:** 3.796 eksekusi di 162 host (153 workstation dan 9 server). Tidak ada satu pun `.js` atau `.jse`; semua eksekusi Februari adalah VBScript. Pola `INC-2026-019` (ekstraksi arsip di `Temp`) dan `Temp` biasa: nol. Kelompok yang tersisa ditinjau satu per satu:

- **share jaringan (3.412 di 153 workstation):** skrip login `map-drives.vbs` dari `NETLOGON`, dijalankan saat pengguna login. Jinak. Parent tercatat `gpscript.exe`; parent persisnya bergantung cara skrip dipasang (GPO atau atribut skrip login di akun), jadi cek di lingkunganmu.
- **lokasi lain (252 di 9 server):** `C:\Scripts\backup-check.vbs` yang dijalankan tugas terjadwal harian, tepat 9 server kali 28 hari. Jinak.
- **profil pengguna (112 di 6 workstation):** `C:\Users\<user>\AppData\Roaming\JAB\logon_old.vbs`, dijalankan dari Run key saat login (parent `explorer.exe`) dan memanggil `cmd.exe /c net use`. Tim IT mengonfirmasi ini sisa skrip login lama yang tidak dibersihkan saat skrip dipindah ke `NETLOGON`. Label: jinak terkonfirmasi, dengan rekomendasi pembersihan Run key dan file.
- **tanpa path absolut (18 di 7 host):** pivot ke `CurrentDirectory` menunjukkan installer driver printer yang menjalankan skrip bawaan Windows dari folder `Printing_Admin_Scripts`. Jinak.
- **downloads (2 di 1 host):** `cscript.exe //nologo` menjalankan `collect_logs.vbs` dari `C:\Users\arif.kurniawan\Downloads\olt-diag-3.1\` di `JKT-WS-0552`, Kamis 2027-02-18 14:02 dan 14:09, parent `cmd.exe`. Arif, engineer NOC, mengunduh paket diagnostik OLT dari portal vendor dan mengekstraknya ke `Downloads` dengan "Extract All", sesuai tiket gangguan OLT hari itu. Label: jinak terkonfirmasi.

Validasi hipotesis: tidak terbukti. Tidak ada skrip yang dijalankan dari folder ekstraksi arsip atau `Temp`, dan dua eksekusi dari `Downloads` serta 112 dari `AppData` dijelaskan pemiliknya. Efek samping yang berguna untuk IT: inventaris VBScript yang masih dipakai di host ber-Sysmon ada empat (`map-drives.vbs`, `backup-check.vbs`, `logon_old.vbs`, dan skrip vendor OLT), semuanya perlu dimigrasi atau dibersihkan sebelum fase 2 deprecation menonaktifkan VBScript secara default.

**Variasi:** untuk 229 workstation tanpa Sysmon, eksekusi historis tidak bisa dilihat, tetapi file skrip yang tertinggal bisa. Kandidat backlog: koleksi Velociraptor dari server hunting `jkt-velo02` yang mencari file `.js`, `.jse`, `.vbs`, dan `.wsf` di `Downloads`, `AppData\Local\Temp`, dan `Desktop`, dikelompokkan per hash. Ini tidak dijalankan hari ini.

**Kapan gagal:** skrip dijalankan lewat asosiasi file tanpa `wscript.exe` di command line yang bisa dibaca (misalnya command line hanya berisi path skrip); path memakai variabel lingkungan atau nama pendek 8.3 yang belum diekspansi; regex `rex` tidak diuji sehingga opsi `//b` dibaca sebagai share; atau skrip dijalankan oleh salinan script host yang tidak punya `OriginalFileName`.

### 2.7 Pivot rantai: shell dan PowerShell yang dimunculkan script host atau proxy binary

Uji lab di bagian 2.4 menunjukkan rantai yang paling menonjol: `mshta.exe` memunculkan `powershell.exe`. Query ini memeriksa rantai itu di data PT JAB, lalu menunjukkan pivot ke 4104 bila rantai ditemukan.

**Tujuan:** menghitung shell dan PowerShell yang parent-nya script host atau proxy binary di Februari.

```
index=sysmon sourcetype=XmlWinEventLog EventCode=1
    earliest="02/01/2027:00:00:00" latest="03/01/2027:00:00:00"
    (ParentImage="*\\wscript.exe" OR ParentImage="*\\cscript.exe" OR ParentImage="*\\mshta.exe"
     OR ParentImage="*\\regsvr32.exe" OR ParentImage="*\\rundll32.exe")
| eval parent=lower(mvindex(split(ParentImage, "\\"), -1)),
       child=lower(if(isnotnull(OriginalFileName) AND OriginalFileName!="-",
                      OriginalFileName, mvindex(split(Image, "\\"), -1)))
| where in(child, "cmd.exe", "powershell.exe", "pwsh.exe", "pwsh.dll")
    OR match(child, "^powershell")
| stats count AS runs dc(host) AS hosts BY parent child
| sort runs
```

| Bagian | Fungsi |
|---|---|
| Filter `ParentImage` | Script host dan tiga proxy binary sebagai parent |
| `child=...` dari `OriginalFileName` | Shell yang diganti nama tetap terbaca sebagai shell |
| `in(child, ...) OR match(child, "^powershell")` | `cmd.exe`, Windows PowerShell, dan PowerShell 7. `match` awalan dipakai supaya nilai asli PowerShell yang membawa akhiran tetap tertangkap; nilai persisnya cek di lab |

Keluaran ilustrasi:

```
parent        child     runs  hosts
wscript.exe   cmd.exe   112   6
cscript.exe   cmd.exe   252   9
```

**Cara membaca hasil:** dua baris, keduanya sudah dijelaskan di bagian 2.6 (`logon_old.vbs` memanggil `net use`, dan `backup-check.vbs` di server). Tidak ada PowerShell yang dimunculkan script host atau proxy binary di host ber-Sysmon selama Februari, dan tidak ada shell yang dimunculkan `mshta.exe`, `regsvr32.exe`, atau `rundll32.exe`.

Bila rantai ke PowerShell ditemukan, pivot berikutnya adalah isi script block di 4104. Query berikut memakai `index=powershell` PT JAB (Script Block Logging aktif di 214 host yang mengirim index itu):

```
index=powershell EventCode=4104
    earliest="02/01/2027:00:00:00" latest="03/01/2027:00:00:00"
| eval sb_len=len(ScriptBlockText)
| where sb_len > 1000
    OR match(ScriptBlockText, "(?i)(FromBase64String|IEX\b|Invoke-Expression|DownloadString|DownloadFile|Net\.WebClient|-enc\b|-w hidden|hidden)")
| stats count values(sb_len) AS lengths BY host
| sort - count
```

| Bagian | Fungsi |
|---|---|
| `len(ScriptBlockText)` dan `sb_len > 1000` | Script block panjang; ambang 1000 adalah titik awal, bukan nilai baku |
| `match(..., "(?i)(...)")` | Pola unduh, eksekusi dinamis, decoding, dan penyembunyian jendela, tanpa peka huruf. Kata `hidden` saja sudah mencakup `-w hidden` dan akan ikut menandai banyak skrip sah; persempit bila hasilnya terlalu banyak |
| `stats ... BY host` | Host dengan script block paling banyak di atas, lalu pivot per host |

Keluaran ilustrasi untuk query ini diambil dari Splunk lab, bukan PT JAB, karena rantai di PT JAB kosong: setelah uji T1218.005 test 2 di bagian 2.4, `jab-lab-win11` muncul dengan beberapa script block berisi skrip info pengguna lokal yang dipanggil test itu, dan tidak ada pola unduh. Di PT JAB, query ini dipakai sebagai pivot per host, bukan sebagai hunt sendiri; hunt 4104 untuk seluruh lingkungan sudah dijalankan sebagai `HUNT-2027-016` (Day 10).

**Variasi:** tambahkan parent Office (`winword`, `excel`, `outlook`) ke filter `ParentImage` untuk melihat Office yang langsung memunculkan PowerShell, pola yang sudah diuji `HUNT-2027-001` untuk Januari.

**Kapan gagal:** 4104 hanya lengkap bila policy Script Block Logging aktif, dan script block yang sangat panjang dipecah menjadi beberapa event; nama field `ScriptBlockText` bergantung add-on; atau rantai melewati perantara yang tidak masuk filter parent.

### 2.8 Laporan tiga hunt

Laporan ini adalah langkah Finalize ketiga hunt, ditulis Kamis sore dengan format yang sama dengan laporan `HUNT-2027-002` (Day 02 bagian 2.6).

```
ID            : HUNT-2027-023                          Selesai: Kamis 2027-03-11 13:00
Hasil         : Tidak ditemukan (tidak terbukti)
Cakupan nyata : 214 host ber-Sysmon, Sysmon EID 1, 2027-02-01 00:00 - 2027-03-01 00:00 WIB
Di luar cakupan: 229 workstation tanpa Sysmon; JKT-WS-0532 setelah 2027-02-02 10:14;
                argumen terobfuscate yang tidak cocok pola teks
Angka         : Tahap A: 76 eksekusi Outlook -> rundll32 (71 FileProtocolHandler https, 5 OpenAs_RunDLL);
                Tahap B: 140 eksekusi bertanda di 4 kelompok jinak; scriptlet/inline 0
Uji positif   : VM lab jab-lab-win11 (bukan PT JAB), 5 test Atomic Red Team (GUID di folder hunt);
                tahap A menangkap Word -> regsvr32; tahap B awalnya lolos mshta "about:" (T1218.005
                test 10), pola diperbaiki, data Februari dijalankan ulang: tetap 140, tanpa tambahan
Deteksi       : Bahan usulan "JAB - Office memunculkan regsvr32, rundll32, atau mshta" dan
                "JAB - proxy binary dengan scriptlet atau skrip inline" -> Sari (diproses di Day 14)

ID            : HUNT-2027-024                          Selesai: Kamis 2027-03-11 15:00
Hasil         : Tidak ditemukan (tidak terbukti); ditemukan-jinak 1 rename, 1 salinan di lokasi salah
Cakupan nyata : Sama dengan -023, plus MDE DeviceProcessEvents 2027-02-09 - 2027-03-01 untuk
                workstation tanpa Sysmon yang punya MDE
Di luar cakupan: File tanpa resource versi; 23 workstation POP tanpa MDE dan Sysmon; MDE sebelum 9 Feb
Angka         : 297 eksekusi di 8 host (hdk-shell.exe 9, PayrollClient regsvr32 76, MSBuild VS 212);
                MDE: PayrollClient regsvr32 27 di 2 host tambahan
Jinak terkonfirmasi: toolkit IT di JKT-WS-0618 (cmd.exe diganti nama, hash identik);
                launcher PayrollClient membawa regsvr32 lama bertanda tangan Microsoft
Tindak lanjut : Tim IT: ganti hdk-shell.exe dengan cmd.exe asli; IT + vendor: launcher PayrollClient
                memakai regsvr32 sistem; Dimas: tinjau status ASR rule "copied or impersonated system
                tools" dan "Office child processes" di konsol MDE (status belum diketahui)
Artefak       : jab_hunt_sysbin_ofn.csv (16 baris) + daftar lokasi resmi tambahan (MSBuild VS)

ID            : HUNT-2027-025                          Selesai: Kamis 2027-03-11 16:30
Hasil         : Tidak ditemukan (tidak terbukti)
Cakupan nyata : Sama dengan -023
Di luar cakupan: 229 workstation tanpa Sysmon (termasuk laptop yang jarang di kantor); skrip lewat
                asosiasi file tanpa script host di command line
Angka         : 3.796 eksekusi wscript/cscript di 162 host; .js/.jse 0; ekstraksi arsip di Temp 0;
                Temp 0; Downloads 2 (vendor OLT, NOC); AppData 112 (logon_old.vbs, 6 host)
Inventaris VBScript untuk IT (sebelum fase 2 deprecation): map-drives.vbs (NETLOGON),
                backup-check.vbs (9 server), logon_old.vbs (6 host, dibersihkan), skrip vendor OLT
Hipotesis baru: Koleksi Velociraptor file skrip di folder user untuk host tanpa Sysmon -> backlog
```

"Tidak ditemukan" di ketiga laporan punya cakupan, angka, jinak yang terkonfirmasi, dan, untuk `-023`, bukti bahwa query menangkap pola yang dicari. Baris uji positif itulah yang membuat Sari bisa percaya bahwa nol di Februari berarti nol, bukan buta.

**Kapan gagal:** perbaikan pola dari uji lab (`about:`) tidak dicatat di laporan. Hunt berikutnya atau rule yang diturunkan dari query lama akan mewarisi celah yang sama tanpa ada yang tahu.

### 2.9 Volume per pola dan jawaban untuk Sari

Tabel ini adalah jawaban pertanyaan keenam Sari dalam bentuk angka. Volume diukur dari 214 host ber-Sysmon selama Februari 2027; baca kolom "Setelah pengecualian sempit", karena itulah yang akan masuk antrean L1.

| Pola | Volume mentah (Feb) | Setelah pengecualian sempit | Usulan |
|---|---|---|---|
| Office memunculkan `regsvr32`/`rundll32`/`mshta` | 76 | 0 (kecuali FileProtocolHandler dengan URL `https` dan `OpenAs_RunDLL` dari folder sementara Outlook) | Rule; bahan usulan untuk Day 14 |
| Proxy binary dengan scriptlet atau skrip inline (`scrobj`, `javascript:`, `vbscript:`, `about:`) | 0 | 0 | Rule; volume nol, setiap kejadian layak ditanya |
| `mshta.exe` dengan argumen selain HTA lokal | 0 (3 HTA lokal) | 0 | Rule, digabung dengan baris di atas |
| `OriginalFileName` tidak cocok dengan nama, atau lokasi di luar daftar resmi | 297 | 85 sebelum IT membersihkan toolkit dan launcher; 0 setelahnya | Laporan mingguan dulu; rule setelah pembersihan |
| `wscript`/`cscript` menjalankan skrip dari Downloads, Temp, atau folder ekstraksi arsip | 2 | 2 (vendor OLT, tanpa pengecualian) | Rule; triage: tanya pengguna dan cek asal file |
| `wscript`/`cscript` menjalankan skrip dari AppData | 112 | 0 setelah `logon_old.vbs` dibersihkan | Ukur ulang setelah pembersihan |
| `rundll32 url.dll,FileProtocolHandler https://...` | 118 | Tidak ada pembeda | Tidak diusulkan |

Angka 85 di baris keempat adalah 297 dikurangi 212 eksekusi MSBuild Visual Studio yang lokasinya ditambahkan ke daftar resmi; sisanya 9 (toolkit IT) dan 76 (PayrollClient) yang menunggu pembersihan. Pengecualian di baris pertama ditulis per kombinasi parent, fungsi, dan bentuk argumen, bukan per host atau per pengguna, karena alasan di bagian 1.4.

Ringkasan berikut kamu kirim ke Sari Kamis pukul 17:00 bersama tiga laporan di bagian 2.8. Setiap baris merujuk subbagian di atas.

| Pertanyaan Sari | Jawaban singkat | Dasar |
|---|---|---|
| Kenapa binary bertanda tangan jadi masalah | Tanda tangan menjawab siapa pembuatnya, bukan untuk apa dipakai; beda jahat dan sah ada di parent, argumen, lokasi, dan konteks | Bagian 1.1 |
| Binary mana dan teknik apa | Katalog LOLBAS untuk daftar dan fungsi; T1218 dan sub-tekniknya (taktik Stealth di v20), T1036.003/.005, T1059 | Bagian 1.2, 1.3 |
| Pola pembeda | Parent tidak lazim, argumen/target tidak lazim, lokasi atau nama salah, kelangkaan; pengecualian sempit sampai argumen | Bagian 1.4, 1.7, 2.2, 2.3 |
| Binary diganti nama | Rule berbasis `Image` buta; pakai `OriginalFileName` dan hash; di PT JAB ada 1 rename sah (toolkit IT) | Bagian 1.5, 2.5 |
| Deprecation VBScript | Tidak menutup `.js` (`INC-2026-019`), dan VBScript masih aktif sampai fase 2; hunt menghasilkan inventaris VBScript untuk IT | Bagian 1.6, 2.6 |
| Pola mana jadi detection | Yang volumenya rendah setelah pengecualian sempit: Office ke proxy binary, scriptlet/inline, script host dari Downloads/Temp; usulan formal diproses di Day 14 | Bagian 1.8, 2.9 |
| Kalau hunt tidak menemukan apa-apa | Uji positif di VM lab; uji itu menemukan dan menutup satu celah (`about:`) sebelum hasil ditulis | Bagian 1.8, 2.4 |

**Kapan gagal:** volume diukur hanya dari satu minggu atau hanya dari workstation. Pola yang jarang di workstation bisa rutin di server (misalnya `cscript.exe` dari tugas terjadwal), dan sebaliknya; ukur di cakupan yang sama dengan cakupan rule yang diusulkan.

## 3. Lab praktik (di VM lab terisolasi)

**Prasyarat:** Splunk lab dengan Sysmon EID 1 (dengan field `OriginalFileName`) dan PowerShell 4104 dari minimal satu VM Windows dengan snapshot bersih; Microsoft Office di VM bila ingin mengerjakan langkah 6; baseline dari Day 05 dan Day 06 bila sudah ada; tabel LOLBAS di bagian 1.2. Ambil prasyarat test Atomic yang mengunduh file pendukung sebelum VM diputus dari internet. Jangan memakai data, nama, atau kejadian dari pekerjaan nyata; PT JAB hanya contoh fiktif.

1. **Daftar LOLBin.** Dari tabel bagian 1.2 (dan LOLBAS bila ingin menambah), pilih 10 LOLBin yang relevan untuk lab-mu. Untuk tiap satu, catat fungsi penyalahgunaan dan pemakaian sah yang kamu harapkan (baseline awal).
2. **Parent-child.** Jalankan query tahap A bagian 2.2 dan variasi `tstats`-nya dengan rentang absolut yang sesuai datamu. Sesuaikan daftar parent sah dari baseline lab. Labeli LOLBin dari parent tidak lazim.
3. **Argumen.** Jalankan query tahap B bagian 2.3, termasuk perbaikan `about:` dari bagian 2.4. Tinjau tiap kelompok dengan konteks parent.
4. **Nama asli dan lokasi.** Jalankan dua langkah bagian 2.5. Catat nilai `OriginalFileName` setiap binary di lookup lab-mu, terutama yang tidak sama persis dengan nama filenya.
5. **Script.** Jalankan query bagian 2.6 dan uji regex-nya dengan tabel kasus positif dan negatif di sana, ditambah minimal dua kasus buatanmu sendiri. Lalu jalankan query rantai dan 4104 di bagian 2.7.
6. **Buktikan menangkap target.** Di VM lab dengan snapshot, jalankan test Atomic dari tabel di bawah. Untuk setiap test, catat jam, lalu jalankan query yang seharusnya menangkapnya. Bila ada yang lolos, perbaiki query dan catat perbaikannya, seperti contoh `about:` di bagian 2.4. Kembalikan snapshot.
7. **Bandingkan dengan rule.** Cek mana yang sudah ditangkap rule yang aktif di lab; yang lolos adalah celah deteksi.
8. **Volume dan handover.** Susun tabel volume per pola seperti bagian 2.9 dari data lab-mu (mentah dan setelah pengecualian sempit), lalu tulis laporan hunt dan satu usulan deteksi dengan format Day 02 bagian 2.7.

Tabel berikut memuat test Atomic yang dirujuk; isinya adalah apa yang dilakukan test dan jejak yang harus terlihat, bukan resep [S3][S4][S23][S25][S26].

| Teknik | Test dan GUID | Apa yang terjadi | Yang harus terlihat di log |
|---|---|---|---|
| T1218.010 | Regsvr32 local COM scriptlet execution, `449aa403-6aba-47ce-8a37-247d21ef0306` [S3] | `regsvr32.exe` diminta mendaftarkan scriptlet `.sct` lokal dari folder atomics lewat `scrobj.dll`; isi scriptlet menjalankan `calc.exe`. Bila scriptlet belum ada, prasyaratnya mengunduh dari GitHub | EID 1 `regsvr32.exe` dengan `/i:` berisi path `.sct` dan `scrobj.dll` di command line; EID 1 `calc.exe` dengan parent `regsvr32.exe`. Tahap B bagian 2.3 menandainya lewat `scrobj`; tahap A hanya bila parent-nya Office |
| T1218.010 | Regsvr32 remote COM scriptlet execution, `c9d0c4ef-8a96-4794-a75b-3d3a5e6f2a36` [S3] | Sama, tetapi scriptlet diambil dari URL. Default-nya URL internet dan bisa diblok Defender | Tambahan EID 3 dari `regsvr32.exe` ke IP luar dan URL di command line. Di lab terisolasi, host file `.sct` di web server lab |
| T1218.005 | Mshta executes VBScript to execute malicious command, `906865c3-e05f-4acc-85c4-fbc185455095` [S4] | `mshta.exe` menjalankan VBScript inline yang memakai objek shell Windows Script Host untuk membuka PowerShell, lalu PowerShell menjalankan script lokal yang menampilkan info user | EID 1 `mshta.exe` dengan `vbscript:` di command line; EID 1 `powershell.exe` dengan parent `mshta.exe`; 4104 berisi isi script lokal. Pola parent `mshta.exe` lalu `powershell.exe` adalah sinyal kuat |
| T1218.005 | Mshta used to Execute PowerShell, `8707a805-2b76-4f32-b1c0-14e558205772` [S4] | `mshta.exe` menjalankan HTA inline berskema `about:` yang membuka PowerShell, mencetak pesan, lalu jeda; tanpa unduhan | EID 1 `mshta.exe` dengan `about:`; EID 1 `powershell.exe` dengan parent `mshta.exe`. Pola tahap B tanpa `about:` melewatkan test ini |
| T1204.002 | Maldoc choice flags command execution, `0330a5d2-a45a-4272-a9ee-e364411c4b18` [S23] | Macro dokumen Word (atau Excel) memunculkan `cmd.exe` dengan perintah `choice`. Harness macro-nya diambil dari GitHub saat test dijalankan | EID 1 `cmd.exe` dengan parent `WINWORD.EXE`; bukti parent Office tercatat |
| T1036.003 | cscript.exe running as notepad.exe, `3a2a578b-0a01-46e4-92e3-62e2859b42f0` [S25] | `cscript.exe` disalin ke `%APPDATA%` dengan nama `notepad.exe` lalu dijalankan; tanpa unduhan | EID 1 dengan `Image` berakhiran `notepad.exe` di `AppData`, `OriginalFileName` milik cscript. Langkah 2 bagian 2.5 menandainya sebagai rename dan lokasi salah |
| T1059.007 | JScript execution to gather local computer information via wscript, `0709945e-4fec-4c49-9faf-c3c292a74484` [S26] | `wscript.exe` menjalankan `sys_info.js` dari folder atomics dan menampilkan empat kotak pesan. Bila skrip belum ada, prasyaratnya mengunduh dari GitHub | EID 1 `wscript.exe` dengan path `.js` di command line. Salin skrip ke `Downloads` atau buka dari dalam arsip ZIP sebelum menjalankannya untuk menguji label lokasi di bagian 2.6 |

Test lain di halaman yang sama ada yang mengunduh payload dari internet; untuk Day ini cukup test di atas.

**Hasil yang sebaiknya tersimpan:**

- Daftar 10 LOLBin dengan fungsi dan baseline pemakaian sah.
- Hunt parent-child dan argumen dijalankan; hasil dilabeli.
- Lookup `OriginalFileName` lab, dengan catatan nilai yang tidak sama persis dengan nama file.
- Hunt binary di lokasi salah atau diganti nama dijalankan.
- Regex lokasi skrip diuji dengan kasus positif dan negatif; hunt wscript/cscript dan pivot PowerShell dijalankan.
- Setiap test Atomic tercatat dengan GUID, jam, dan query yang menangkapnya; perbaikan query bila ada yang lolos.
- Tabel volume per pola, laporan hunt, dan satu usulan deteksi.

**Variasi tantangan:** pilih satu LOLBin yang lab-mu belum punya rule-nya (misalnya `installutil` atau `cmstp`). Ambil fungsi penyalahgunaannya dari tabel bagian 1.2, rancang hipotesis ABLE, dan jalankan hunt. Bila menemukan pola, tulis usulan deteksi; bila tidak ada pemakaian sama sekali di lab, catat sebagai "tidak ditemukan" dengan cakupan (binary itu memang tidak dipakai, yang justru memudahkan deteksi bila muncul). Tantangan kedua: matikan FOD VBScript di VM lab Windows 11 (bila versi Windows-mu sudah menyediakannya), lalu jalankan ulang skrip `.vbs` dan `.js` dari test T1059.007. Catat mana yang masih berjalan dan event apa yang muncul; hasil ini adalah bukti pertamamu tentang apa yang benar-benar berubah setelah fase 2.

## 4. Troubleshooting

Tabel ini memuat masalah yang sering muncul saat menjalankan hunt LOLBin dan script host. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Hunt LOLBin penuh FP | Daftar parent sah belum disesuaikan | Bangun baseline parent per LOLBin (Day 05) |
| `OriginalFileName` kosong | TA tidak mengisi, versi Sysmon lama, atau file tanpa resource versi | Cek event mentah; pakai `Image` dan hash; catat blind spot rename |
| Lookup `jab_hunt_sysbin_ofn.csv` kosong atau kurang baris | Pola lokasi resmi salah escape, atau `ofn` tidak di-`lower()` | Jalankan langkah 1 bagian 2.5 tanpa `outputlookup` dulu dan periksa barisnya |
| Semua path `Program Files` muncul sebagai "lokasi salah" | Daftar pantauan memuat binary yang juga dibawa produk sah (MSBuild) | Tambah path produk resmi sebagai daftar sempit, jangan melonggarkan pola |
| PowerShell 4104 kosong | Script Block Logging nonaktif | Aktifkan policy `Turn on PowerShell Script Block Logging`; sampai aktif, celah visibilitas |
| Semua pemakaian PowerShell ditandai | Ambang panjang terlalu rendah; pola `hidden` terlalu umum; tanpa konteks | Naikkan ambang; persempit pola; tambah konteks user/host |
| LOLBin langka tidak muncul | Memang tidak dipakai di lab | "Tidak ditemukan" sah; mudah dideteksi bila muncul |
| Argumen cocok tapi sah | Installer/admin sah | Allowlist sempit (parent + fungsi + bentuk argumen); bandingkan baseline |
| Test Atomic lolos dari query | Bentuk argumen yang belum ada di pola (misalnya `about:`), atau parent di luar daftar | Perbaiki pola, ulangi test, catat perbaikan di laporan (bagian 2.4) |
| Test Atomic tidak menghasilkan event sama sekali | Defender memblok sebelum proses dibuat, atau prasyarat belum diunduh | Cek log Defender di VM; ambil prasyarat sebelum isolasi; jangan matikan proteksi di luar VM lab |
| `rex` lokasi skrip menangkap opsi `//b` sebagai share | Pola share tidak mensyaratkan `//host/` | Pakai pola bagian 2.6 dan uji dengan tabel kasusnya |
| Query MDE kosong untuk awal bulan | Retensi advanced hunting 30 hari | Tulis rentang nyata di laporan; jangan menyebut "Februari penuh" |

## 5. Kesalahan umum dan jebakan

- **Menandai LOLBin berdasarkan nama.** Binary-nya sah; fokus pada parent, argumen, lokasi, dan konteks.
- **Daftar hitam tanpa baseline.** Menghasilkan ribuan FP; LOTL butuh baseline per binary.
- **Pengecualian selebar fungsi.** Mengecualikan semua `url.dll,FileProtocolHandler` ikut membutakan varian yang menjalankan perintah lokal [S24]; pengecualian ditulis sampai bentuk argumen dan parent (bagian 1.4).
- **Mengabaikan konteks aset dan user.** msbuild di workstation developer normal; di finance tidak.
- **Mengira satu rule LOLBin menutup teknik.** Tiap LOLBin dan tiap pemakaian adalah prosedur berbeda; hitung cakupan per prosedur.
- **Percaya penuh pada `OriginalFileName`.** Nilainya bisa kosong dan bisa diedit; konfirmasi dengan hash dan lokasi, dan ambil pemetaannya dari data sendiri (bagian 1.5).
- **Menulis "tidak ditemukan" tanpa uji positif.** Di bagian 2.4, uji lab menemukan bahwa pola tahap B buta terhadap `mshta` berskema `about:`. Tanpa uji itu, hasil Februari akan terlihat bersih untuk alasan yang salah.
- **Menganggap deprecation VBScript menutup masalah script host.** JScript tidak disebut di deprecation, dan VBScript masih aktif sampai fase 2 berlaku dan bisa dinyalakan kembali (bagian 1.6).
- **Menjalankan contoh command line LOLBAS atau test Atomic di mesin kerja.** LOLBAS adalah referensi perilaku; uji hanya di VM lab dengan test terdokumentasi.
- `[komunitas, belum terkonfirmasi]` Praktisi umumnya menilai deteksi berbasis perilaku (parent, argumen) jauh lebih tahan daripada daftar nama binary, karena penyerang mudah me-rename binary tetapi sulit mengubah rantai parent dan argumen. Data peringkat Red Canary (bagian 1.1) mendukung pentingnya interpreter; ketahanan relatif kedua pendekatan perlu diukur di lingkunganmu.

## 6. Catatan terkini

Bagian ini menampung versi, tanggal, dan perubahan platform yang berkaitan dengan Day ini. Berguna saat membuka sumbernya; yang mengubah keputusan hunt sudah ditulis di bagian 1 dan 2.

- **ATT&CK v20:** T1218 versi 4.0 (diubah 2026-05-12) dengan 14 sub-teknik dan detection strategy DET0081 [S1]; taktik TA0005 bernama Stealth [S13]. ID teknik lama (T1218.xxx, T1127, T1059, T1036) tetap. T1036.005 versi 3.0 diubah 2026-09-11 dan kini mencakup platform Containers dan ESXi [S9]; T1059.001 versi 1.6 diubah 2026-09-18 [S10].
- **LOLBAS** terus bertambah; per 2026-10-18 halaman indeks memuat sekitar 245 entri. Perlakukan sebagai referensi hidup, bukan daftar statis [S2].
- **Red Canary Threat Detection Report 2026 (data 2025)** menempatkan PowerShell dan Windows Command Shell di peringkat 2 dan 3; peringkat 1 adalah Cloud Accounts (T1078.004), tanda bahwa identitas cloud kini bersaing dengan LOTL endpoint. Malicious Copy and Paste (T1204.004) ada di peringkat 8 [S6]; pola ini sering berujung pada pengguna yang menjalankan perintah `mshta` atau PowerShell sendiri, dan test Atomic T1204.002 kini memuat simulasinya [S23].
- **VBScript:** deprecated sejak Oktober 2023; halaman Microsoft per 2026-09-23 masih menyebutnya FOD yang dipasang sejak awal; fase 2 (nonaktif secara default) disebut sekitar 2026 atau 2027 tanpa tanggal pasti; fase 3 belum dijadwalkan [S18][S19][S20]. Microsoft 365 versi 2508 ke atas membawa kelas RegExp di VBA, sehingga macro Office tidak lagi bergantung pada library RegExp VBScript [S20].
- **WMIC:** menurut halaman Microsoft, sejak pembaruan Agustus 2026 WMIC dihapus dan tidak lagi tersedia sebagai FOD di Windows 11 24H2 ke atas; WMI sendiri tidak terdampak [S18]. Konsekuensinya untuk hunting ada di bagian 2.5.
- **ASR rules reference** (diperbarui 2026-09-09) memuat rule "Block all Office applications from creating child processes" (`d4f940ab-401b-4efc-aadc-ad5f3c50688a`, action type advanced hunting `AsrOfficeChildProcessAudited`/`Blocked`, hanya berlaku bila Office terpasang di `Program Files`) dan "Block use of copied or impersonated system tools" (`c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb`, `AsrAbusedSystemToolAudited`/`Blocked`) [S21]. Mode audit kedua rule bisa menjadi sumber data tambahan untuk hunt `-023` dan `-024` di host MDE tanpa Sysmon.
- **Sysmon v15.22** (halaman Microsoft Learn diperbarui 2026-09-10) mendaftar event sampai EID 29; EID 7 (image loaded) tetap nonaktif secara default [S5].
- Day 14 mengubah hasil hunt Day 12 dan Day 13 menjadi detection, termasuk bahan usulan dari `HUNT-2027-023`.

## 7. Cheat sheet

```
LOTL        pakai binary/script bawaan (sah, bertanda tangan) ; beda jahat vs sah ada di CARA pakai
LOLBAS      peta binary bawaan yg bisa disalahgunakan + fungsi (Execute/Download/AWL bypass/...) ; referensi, bukan daftar deteksi
TEKNIK v20  T1218 proxy exec (Stealth): rundll32 .011 | regsvr32 .010 | mshta .005 | msiexec .007 | installutil .004
            | cmstp .003 | regsvcs/regasm .009 | odbcconf .008 ; T1127.001 msbuild ; T1105 certutil/bitsadmin
            T1036.003 rename | T1036.005 nama/lokasi meniru ; T1059 .001 PS | .003 cmd | .005 VBScript | .007 JScript
POLA LOLBIN parent tak lazim (Office/script/WmiPrvSE) | argumen tak lazim (URL, folder user, scrobj, javascript:,
            vbscript:, about:, .hta, atau argumen kosong) | lokasi/nama salah | binary langka
NAMA ASLI   OriginalFileName (resource versi PE) vs Image ; pemetaan diambil dari data di System32/SysWOW64/.NET ;
            kosong = "-" ; konfirmasi dengan Hashes
POLA SCRIPT wscript/cscript dari Downloads/Temp/ekstraksi arsip/AppData | PS 4104 panjang/enc/IEX/download
            | cmd rantai/obfuscation ; rex path skrip: buang path host dulu, //host/ untuk share, \b untuk ekstensi
VBSCRIPT    deprecated (Okt 2023) ; fase 1 FOD aktif | fase 2 ~2026/2027 nonaktif default | fase 3 dihapus (TBD)
            JScript (.js) TIDAK disebut -> pola INC-2026-019 tetap hidup
WAJIB       baseline per binary + konteks aset/user ; pengecualian sempit sampai bentuk argumen
UJI POSITIF test Atomic jinak di VM lab -> jalankan query yg sama -> lolos? perbaiki query SEBELUM tulis "tidak ditemukan"
VOLUME      mentah | setelah pengecualian sempit | host ; rendah -> rule ; tinggi tanpa pembeda -> laporan/tidak diusulkan
HANDOVER    cakupan per prosedur (1 rule certutil != rundll32) ; usulan formal ke pemilik konten detection
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Karena `rundll32.exe url.dll,FileProtocolHandler` sudah terbukti jinak di PT JAB, rule baru cukup mengecualikan semua command line yang memuat `url.dll,FileProtocolHandler`." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Yang terbukti jinak adalah bentuk dengan argumen URL `https://` dari Outlook dan aplikasi chat kantor. Fungsi yang sama juga bisa dipakai menjalankan perintah lokal, dan Atomic Red Team punya test T1218.011 yang melakukan persis itu. Pengecualian yang benar mensyaratkan bentuk argumen (URL web) dan parent yang dikenal, sehingga varian dengan path lokal tetap masuk antrean. Lihat bagian 1.4 dan 2.2.

</details>

**2. Skenario keputusan.** Query tahap A dan tahap B `HUNT-2027-023` atas data Februari tidak menemukan apa pun selain kelompok jinak. Laporan harus dikirim ke Sari sore ini. Langkah mana yang paling tepat?

- A. Kirim laporan "tidak ditemukan" sekarang, karena 214 host dan satu bulan penuh sudah diperiksa.
- B. Jalankan test Atomic yang jinak di VM lab dengan konfigurasi Sysmon yang sama, jalankan query yang sama atas data lab, perbaiki query bila ada test yang lolos, jalankan ulang atas data Februari, lalu tulis hasil beserta bukti uji.
- C. Jalankan test Atomic di satu workstation produksi yang sedang tidak dipakai, supaya telemetrinya identik dengan produksi.

<details><summary>Jawaban</summary>

B. Uji positif membuktikan bahwa nol berarti nol, bukan query yang buta, dan di kasus ini uji itu menemukan bahwa pola tahap B melewatkan `mshta` berskema `about:`. A keliru karena "tidak ditemukan" dari query yang belum diuji bisa saja hasil kebutaan query. C keliru karena test Atomic hanya dijalankan di lab terisolasi dengan snapshot, tidak pernah di host produksi; kemiripan telemetri dicapai dengan menyalin konfigurasi Sysmon ke VM lab. Lihat bagian 1.8 dan 2.4.

</details>

**3. Pertanyaan jebakan.** "Bila `OriginalFileName` sebuah proses sama dengan nama filenya, binary itu pasti asli dan berada di tempat yang benar." Benarkah?

<details><summary>Jawaban</summary>

Tidak. `OriginalFileName` hanya menjawab apakah nama file cocok dengan nama asli di resource versi. Salinan di lokasi salah punya nama yang sama, seperti `regsvr32.exe` di folder PayrollClient, sehingga lokasi harus diperiksa terpisah. Nilai itu juga bisa kosong atau diedit, walaupun mengedit file mengubah hash-nya. Konfirmasi dilakukan dengan lokasi dan hash, bukan dengan satu field. Lihat bagian 1.5 dan 2.5.

</details>

**4. Skenario keputusan.** `HUNT-2027-024` menemukan `hdk-shell.exe` di `JKT-WS-0618` dengan `OriginalFileName` milik `cmd.exe`, dan pemiliknya mengonfirmasi itu toolkit lama tim IT. Apa tindak lanjut yang paling tepat?

- A. Tambahkan `JKT-WS-0618` ke pengecualian rule rename supaya tidak muncul lagi.
- B. Label jinak terkonfirmasi, catat hash identik dengan `cmd.exe`, minta tim IT mengganti salinan itu dengan `cmd.exe` asli, dan jadikan pola rename laporan mingguan sampai pembersihan selesai sebelum diusulkan sebagai rule.
- C. Nyatakan insiden, karena rename binary sistem adalah teknik T1036.003.

<details><summary>Jawaban</summary>

B. Kejadian itu dijelaskan pemiliknya dan didukung hash, jadi jinak; tetapi perilakunya sama dengan teknik penyerang, sehingga solusi terbaik adalah menghilangkan penyebabnya, bukan membuat pengecualian. Volume 85 sebelum pembersihan juga menjadi alasan pola ini dimulai sebagai laporan. A keliru karena pengecualian per host membutakan rule tepat di workstation helpdesk yang punya akses luas. C keliru karena teknik yang cocok belum berarti insiden; label ditentukan oleh bukti dan konfirmasi pemilik. Lihat bagian 2.5 dan 2.9.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Gilang Ramadhan (analyst L1), dalam tiga kalimat, kenapa deprecation VBScript tidak membuat pola `INC-2026-019` hilang.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Di `INC-2026-019` file yang dijalankan adalah `.js`, yaitu JScript, dan sumber resmi Microsoft hanya membahas penghapusan VBScript, bukan JScript, jadi `wscript.exe` tetap bisa menjalankan file seperti itu. VBScript sendiri juga belum mati: sampai fase 2, sekitar 2026 atau 2027 tanpa tanggal pasti, ia masih aktif secara default, dan admin bisa menyalakannya kembali. Jadi alert untuk `wscript` atau `cscript` yang menjalankan skrip dari `Downloads`, `Temp`, atau folder ekstraksi arsip tetap perlu kamu tanggapi serius."

Kesalahan yang sering muncul:
- Menyamakan VBScript dengan seluruh Windows Script Host, padahal `wscript.exe` juga menjalankan JScript.
- Menyebut tanggal pasti fase 2, padahal sumber resmi tidak menyebutnya.
- Lupa mengaitkan dengan pekerjaan L1, yaitu alert yang tetap akan muncul.

</details>

**6. Pertanyaan jebakan.** "Query tahap A `HUNT-2027-023` sudah memakai filter `OriginalFileName`, jadi rantai Word yang memunculkan `cmd.exe` lalu `regsvr32.exe` dengan scriptlet pasti tertangkap tahap A." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Filter `OriginalFileName` hanya menutup rename. Tahap A mensyaratkan parent langsung proxy binary adalah aplikasi Office, sedangkan di rantai itu parent `regsvr32.exe` adalah `cmd.exe`. Rantai dengan perantara ditangkap tahap B, yang memeriksa argumen seperti `scrobj` untuk semua parent. Karena itu kedua tahap dijalankan bersama. Lihat bagian 1.4, 2.2, dan 2.3.

</details>

**7. Interview question (English).** "How would you hunt for living-off-the-land binary abuse without drowning in false positives?"

<details><summary>Sample answer</summary>

"I never hunt on the binary name alone, because rundll32 or regsvr32 run hundreds of thousands of times a week for legitimate reasons. I split the question into behaviours: unusual parents such as Office spawning a proxy binary, unusual arguments such as scriptlets, inline script schemes or URLs, binaries running from the wrong place or under a different name, which I check by comparing Sysmon's OriginalFileName with the image path and the hash, and script hosts running files from Downloads or Temp. For each behaviour I measure the raw volume in our own data, then write exclusions that are narrow down to the parent and argument shape, never per host. Before I report 'nothing found', I run benign Atomic Red Team tests in an isolated lab with the same Sysmon config and confirm the query catches them; in one hunt that showed my mshta pattern missed the about: scheme, so I fixed it first. The patterns that stay at near-zero volume after narrow exclusions go to the detection owner as rule proposals; the noisy ones become periodic reports or are explicitly not proposed."

What makes this answer strong: it frames the problem as behaviour rather than names, shows how volume is measured before anything reaches an analyst queue, treats rename detection with more than one field, and proves the query is not blind before trusting a negative result.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | MITRE ATT&CK: T1218 System Binary Proxy Execution, T1127, T1059 | https://attack.mitre.org/techniques/T1218/ | primer | diakses 2026-10-09, dicek ulang 2026-10-18 (ATT&CK v20; T1218 versi 4.0, diubah 2026-05-12) | Tinggi. Subteknik per binary (14 di v20), taktik Stealth, detection strategy DET0081 |
| S2 | LOLBAS Project | https://lolbas-project.github.io/ | sekunder (proyek komunitas) | diakses 2026-10-10, dicek ulang 2026-10-18 | Sedang-tinggi. Daftar binary, kategori fungsi, ID ATT&CK; referensi hidup. Jumlah entri per 2026-10-18 dari hitungan halaman indeks, sekitar 245 |
| S3 | Atomic Red Team: T1218.010 | https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.010/T1218.010.md | primer | diakses 2026-10-10, dicek ulang 2026-10-18 | Tinggi. Isi test dan GUID; test 1 mengunduh scriptlet dari GitHub bila belum ada |
| S4 | Atomic Red Team: T1218.005 | https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.005/T1218.005.md | primer | diakses 2026-10-10, dicek ulang 2026-10-18 | Tinggi. Isi test dan GUID, termasuk test 10 (`about:`) |
| S5 | Microsoft Learn: Sysmon (EID 1, `OriginalFileName`) | https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon | primer | diakses 2026-10-10, dicek ulang 2026-10-18 (halaman diperbarui 2026-09-10) | Tinggi. Field process create, EID 7 nonaktif default, daftar event sampai EID 29. Halaman tidak merinci field `OriginalFileName` |
| S6 | Red Canary Threat Detection Report: Techniques | https://redcanary.com/threat-detection-report/techniques/ | sekunder (laporan vendor) | diakses 2026-10-10, dicek ulang 2026-10-18 | Sedang-tinggi. Peringkat teknik dari data pelanggan satu vendor; edisi 2026, data 2025 |
| S7 | MITRE ATT&CK: T1218.011 Rundll32 | https://attack.mitre.org/techniques/T1218/011/ | primer | ATT&CK v20; versi 3.0, diubah 2026-05-12; diakses 2026-10-18 | Tinggi. `javascript:`, `Control_RunDLL`, ordinal, rename rundll32, Raspberry Robin tanpa argumen, DET0475 |
| S8 | MITRE ATT&CK: T1036.003 Rename Legitimate Utilities | https://attack.mitre.org/techniques/T1036/003/ | primer | ATT&CK v20; versi 3.0, diubah 2026-05-12; diakses 2026-10-18 | Tinggi. Salin, pindah, dan ganti nama utility; DET0005 dengan pencocokan metadata PE |
| S9 | MITRE ATT&CK: T1036.005 Match Legitimate Resource Name or Location | https://attack.mitre.org/techniques/T1036/005/ | primer | ATT&CK v20; versi 3.0, diubah 2026-09-11; diakses 2026-10-18 | Tinggi. Nama dan lokasi yang meniru program sah; DET0347 |
| S10 | MITRE ATT&CK: T1059.001 PowerShell | https://attack.mitre.org/techniques/T1059/001/ | primer | ATT&CK v20; versi 1.6, diubah 2026-09-18; diakses 2026-10-18 | Tinggi. DET0455 |
| S11 | MITRE ATT&CK: T1059.005 Visual Basic | https://attack.mitre.org/techniques/T1059/005/ | primer | ATT&CK v20; versi 1.5, diubah 2026-05-12; diakses 2026-10-18 | Tinggi. VBScript bawaan Windows; DET0076 menekankan rantai perilaku script host |
| S12 | MITRE ATT&CK: T1059.007 JavaScript | https://attack.mitre.org/techniques/T1059/007/ | primer | ATT&CK v20; versi 2.2, diubah 2026-05-12; diakses 2026-10-18 | Tinggi. JScript lewat wscript/cscript/HTA; DET0264 |
| S13 | MITRE ATT&CK: TA0005 Stealth | https://attack.mitre.org/tactics/TA0005/ | primer | ATT&CK v20; diubah 2026-05-12; diakses 2026-10-18 | Tinggi untuk nama dan deskripsi taktik. Halaman tidak menyebut nama lama Defense Evasion |
| S14 | LOLBAS Project: Regsvr32 | https://lolbas-project.github.io/lolbas/Binaries/Regsvr32/ | komunitas (katalog terkurasi) | diakses 2026-10-18 | Sedang-tinggi. Path, fungsi Execute/AWL bypass, hak user, IOC |
| S15 | LOLBAS Project: Rundll32 | https://lolbas-project.github.io/lolbas/Binaries/Rundll32/ | komunitas (katalog terkurasi) | diakses 2026-10-18 | Sedang-tinggi. Path, fungsi Execute dan ADS (T1564.004), IOC koneksi keluar |
| S16 | LOLBAS Project: Mshta | https://lolbas-project.github.io/lolbas/Binaries/Mshta/ | komunitas (katalog terkurasi) | diakses 2026-10-18 | Sedang-tinggi. Path, Execute, ADS (tidak bekerja di Windows 10 1903 ke atas), Download ke INetCache |
| S17 | LOLBAS Project: Certutil | https://lolbas-project.github.io/lolbas/Binaries/Certutil/ | komunitas (katalog terkurasi) | diakses 2026-10-18 | Sedang-tinggi. Download (T1105), ADS, Encode (T1027.013), Decode (T1140), IOC file baru dan user-agent |
| S18 | Microsoft Learn: Deprecated features in the Windows client | https://learn.microsoft.com/en-us/windows/whats-new/deprecated-features | primer | halaman 2026-09-23; diakses 2026-10-18 | Tinggi. VBScript deprecated (Oktober 2023) dan akan menjadi FOD; pembaruan Agustus 2026: WMIC dihapus di Windows 11 24H2 ke atas |
| S19 | Microsoft Learn: Resources for deprecated features (VBScript) | https://learn.microsoft.com/en-us/windows/whats-new/deprecated-features-resources | primer | halaman 2026-09-23; diakses 2026-10-18 | Tinggi. FOD VBScript awalnya dipasang sejak awal sebelum dihentikan |
| S20 | Microsoft 365 Developer Blog: How to prepare VBA projects for VBScript deprecation | https://devblogs.microsoft.com/microsoft365dev/how-to-prepare-vba-projects-for-vbscript-deprecation/ | primer (blog resmi Microsoft) | 2025-09-09 (Wenjun Gong); diakses 2026-10-18 | Tinggi. Tiga fase (fase 2 sekitar 2026 atau 2027, fase 3 TBD), RegExp di VBA sejak versi 2508 |
| S21 | Microsoft Learn: ASR rules reference | https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference | primer | halaman 2026-09-09; diakses 2026-10-18 | Tinggi. GUID dan action type rule Office child process dan copied or impersonated system tools |
| S22 | Microsoft Learn: DeviceProcessEvents table | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table | primer | halaman 2026-08-07; diakses 2026-10-18 | Tinggi. Kolom `ProcessVersionInfoOriginalFileName`, `FileName`, `FolderPath` |
| S23 | Atomic Red Team: T1204.002 | https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md | primer | diakses 2026-10-18 | Tinggi. Test 3 (Word memunculkan cmd), harness macro diambil dari GitHub; tidak ada test yang langsung memunculkan proxy binary |
| S24 | Atomic Red Team: T1218.011 | https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.011/T1218.011.md | primer | diakses 2026-10-18 | Tinggi. Test 2 (VBScript tanpa unduhan), test 15 (perintah lewat FileProtocolHandler) |
| S25 | Atomic Red Team: T1036.003 | https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.003/T1036.003.md | primer | diakses 2026-10-18 | Tinggi. Test 3 (cscript sebagai notepad.exe di `%APPDATA%`, tanpa unduhan) |
| S26 | Atomic Red Team: T1059.007 | https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.007/T1059.007.md | primer | diakses 2026-10-18 | Tinggi. Test 2 (wscript menjalankan `sys_info.js`) |
| S27 | EventSentry: Sysmon | https://www.eventsentry.com/sysmon | sekunder (vendor) | diakses 2026-10-18 | Sedang. Menyebut `OriginalFileName` dibaca dari resource versi executable, sehingga binary yang diganti nama tetap dikenali |
| S28 | Olaf Hartong: Sysmon schema manifest (gist) | https://gist.github.com/olafhartong/42b93050b6e0f49742cc3ea151d97f12 | komunitas | 2021-04-02; diakses 2026-10-18 | Sedang. Manifest skema 4.60 (binary 14.0) memuat `OriginalFileName` di EID 1 dan EID 7 |

**Catatan sumber:** tabel fungsi LOLBAS diambil per 2026-10-10 dan dicek ulang per 2026-10-18; isinya bisa berubah, dan jumlah 245 entri adalah hitungan dari halaman indeks, bukan angka resmi proyek. Halaman peringkat Red Canary menyebut data 2025 untuk edisi 2026, tetapi masih memuat sisa teks edisi lama. Klaim bahwa `OriginalFileName` tercatat sejak Sysmon 10 belum dikonfirmasi sumber primer Microsoft; halaman Sysmon [S5] tidak merinci field ini, sehingga keberadaan field didukung manifest skema komunitas [S28] dan penjelasan vendor [S27]. Nilai `OriginalFileName` per binary (huruf besar-kecil, akhiran tambahan) perlu dicek di lab-mu. Tanggal pasti fase 2 deprecation VBScript tidak ada di sumber resmi yang diperiksa, dan sumber itu tidak menyebut JScript; pernyataan bahwa JScript tidak termasuk adalah pembacaan dari tidak adanya penyebutan, jadi uji di lab (variasi tantangan bagian 3) sebelum dipakai sebagai argumen formal. Pola nama folder ekstraksi arsip (`Temp1_`, `Rar$`, `7z`) dan parent proses skrip login (`gpscript.exe`) perlu dicek di versi Windows dan software lab-mu. Nama index 4104 dan field `ScriptBlockText` bergantung add-on. Macro `security_content_summariesonly` dan data model Endpoint perlu dicek ketersediaannya di search head-mu. Situasi Sari, pelajaran `INC-2026-019` sebagaimana ditulis di sini, seluruh isi `HUNT-2027-023` sampai `HUNT-2027-025` (host, akun, angka, label), VM lab `jab-lab-win11`, dan tabel volume adalah penerapan catatan ini pada organisasi fiktif, bukan hasil eksekusi nyata.
