---
day: 47
title: 'Review akhir: seluruh jalur Splunk dari fondasi L1 sampai sintesis, dan rencana memperkuat kelemahan'
researched_on: 2026-10-15
versions_checked: 'Splunk Enterprise 10.6 (SPL 10.x); ES 8.7.0; CIM 6.4; Splunk SOAR (On-premises) 8.6.0; ESCU v6.7.0; SSE 3.8.3; MITRE ATT&CK v19.2'
---

# Day 47: Review akhir dan rencana memperkuat kelemahan

Cakupan: ringkasan seluruh 47 Day dengan rincian untuk hunting, respons dan otomasi, platform, dan sintesis (Day 38-46), peta konsep yang menyambungkan jalur dari fondasi L1 sampai Enterprise Security, jejak satu kasus PT JAB dari ujung ke ujung, glosarium, lab gabungan, dan rencana memperkuat bagian yang masih lemah.

## Ide inti

Empat puluh enam Day sebelumnya membangun satu rantai, walaupun dipelajari per mata rantai: data masuk dengan label yang benar, SPL dan knowledge object mengubahnya menjadi jawaban yang bisa diulang, data model dan CIM membuat jawaban itu berlaku lintas vendor, konteks ancaman dan ES mengubahnya menjadi finding yang diprioritaskan, hunting mencari yang belum tertangkap detection, respons menindaklanjutinya, dan platform menentukan apakah semua itu benar-benar mencakup rentang waktu yang kamu klaim. Sebuah kesimpulan di laporan investigasi hanya sekuat mata rantai terlemah di belakangnya. Karena itu kemampuan yang diuji di review akhir bukan hafalan command, tetapi kemampuan mengambil satu kasus lalu menunjukkan, mata rantai demi mata rantai, kenapa kesimpulannya bisa dipercaya dan di mana batasnya.

Analoginya dari layar NOC. Alarm di layar hanya bisa dipercaya bila ada titik monitoring di segmen itu, polling-nya masih berjalan, template alarm cocok dengan counter yang benar-benar dikirim perangkat, dan tiketnya ditangani dengan runbook yang jelas. Batasnya ada pada arti layar yang tenang. Gangguan hanya terlihat di segmen yang dipantau, grafik yang rata bisa berarti polling berhenti, dan template yang terpasang tanpa counter yang cocok diam selamanya. Di SOC, keadaan yang sama lebih berbahaya: sumber log yang diam bisa berarti agent dimatikan penyerang, sehingga ia diperlakukan sebagai temuan keamanan, dan detection yang aktif di atas data model kosong terlihat persis seperti lingkungan yang aman.

```
data masuk (A) -> SPL + knowledge object (B, C) -> data model + CIM (D) -> konteks ancaman (E)
   -> detection, RBA, finding, investigasi (F) -> respons: AR dan playbook (H)
hunting (G) mencari yang lolos dari F, lalu Act: detection baru kembali ke F
platform (I) menjawab: apakah data, jadwal, dan akses benar-benar mendukung semua di atas
sintesis (J): satu kasus ditelusuri lewat empat sudut, ditutup dengan keterbatasan dan detection baru
```

Situasi yang dipakai di Day ini: PT Jaringan Anak Bangsa (PT JAB, ISP menengah fiktif) bersiap memindahkan alert L1 dari app Search & Reporting ke ES yang baru diadopsi di search head terpisah. SOC lead meminta setiap analyst L2 menguji kesiapannya dengan satu kasus yang sudah ditutup:

> "Ambil SOC-2026-0283, kasus `svc_backup` yang dipakai untuk lateral movement. Telusuri dari belakang. Saya ingin tahu dari mana datanya, kenapa query-nya bisa dipercaya, kenapa sinyal itu sampai ke kita, apa yang kita lakukan dan siapa yang boleh melakukannya, dan apa yang sebenarnya tidak bisa kita lihat. Lalu bilang mata rantai mana yang paling lemah."

Permintaan itu bisa dipecah menjadi enam pertanyaan:

1. Data apa yang menopang kasus itu, dan bagaimana membuktikannya lengkap? (fondasi dan platform)
2. Apa yang membuat query-nya bisa dipindahkan antar sumber dan tetap benar? (SPL lanjutan, knowledge object, data model)
3. Kenapa sinyal itu muncul, dan bagaimana ia diprioritaskan? (hunting, baseline, konteks aset dan identitas)
4. Bagaimana investigasinya berjalan sampai kesimpulan? (lima tahap, empat sudut pivot)
5. Tindakan apa yang diambil, otomatis atau dengan persetujuan? (adaptive response dan SOAR)
6. Apa yang tidak terlihat, dan apa yang lahir dari kasus itu? (keterbatasan dan detection baru)

Ringkasan per bagian ada di bagian 1.1 sampai 1.8, dengan rincian untuk hunting, respons, platform, dan sintesis di bagian 1.5 sampai 1.8. Bagian 1.9 menjawab keenam pertanyaan SOC lead dengan artefak PT JAB. Lab di bagian 2-4 memintamu melakukan hal yang sama untuk kasus lain, lalu menyusun rencana memperkuat mata rantai yang paling lemah di dirimu sendiri.

**Kapan relevan:** setelah menyelesaikan seluruh topik Splunk, sebelum interview untuk posisi L2 atau detection engineering, sebelum memindahkan pekerjaan dari Splunk Enterprise biasa ke ES, dan saat menulis atau mereview laporan investigasi yang menyimpulkan "tidak ada bukti".
**Kapan bukan jawaban:** review ini tidak menambah fakta baru. Bila ada yang terasa baru atau kabur, kembali ke Day asalnya. Review ini juga bukan pengganti lab: rencana di bagian 2-4 baru bernilai bila setiap baris berujung pada bukti yang kamu hasilkan sendiri.

## 1. Ringkasan, peta konsep, dan glosarium

Ringkasan Bagian A sampai F sengaja padat karena tiga Day review sebelumnya (Day 10, Day 20, dan Day 37) sudah merangkumnya lebih rinci. Bagian G sampai J belum pernah direview, jadi ringkasannya lebih panjang.

### 1.1 Fondasi analyst (Day 01-09)

- **Day 01:** setiap search adalah empat keputusan: index, sourcetype, rentang waktu, dan search mode. `_time` adalah waktu kejadian, `_indextime` waktu masuk, dan selisihnya adalah ingest lag. Dataset statis seperti BOTS dicari rentangnya dulu, lalu dipakai rentang absolut. Snap-to (`-1d@d` sampai `@d`) membuat rekap bermakna tetap.
- **Day 02:** pipeline SPL membuang apa yang tidak dibawa ke tahap berikutnya. `search` menyaring nilai tanpa peka huruf, `where` mengevaluasi ekspresi dan peka huruf. `NOT field=*` mengembalikan event tanpa field itu, sedangkan `field!=*` selalu kosong. Batas bawaan `sort`, `top`, dan `list()` diam-diam memotong hasil.
- **Day 03:** log Windows Security dibaca lewat logon type, Status dan SubStatus 4625, serta pemisahan Subject dan target yang di format klasik menjadi field multivalue. Satu sesi disambung lewat LogonId. 4688 butuh audit command line, dan 1102 selalu diselidiki.
- **Day 04:** isi Sysmon ditentukan konfigurasinya. Process tree dibangun dari `ProcessGuid` dan `ParentProcessGuid`, akses ke LSASS dari EID 10, dan isi script PowerShell 4104 yang terpecah disatukan per `ScriptBlockId`.
- **Day 05:** firewall, proxy, DNS, dan VPN dipetakan ke data model masing-masing. HTTPS lewat proxy hanya meninggalkan host dan port, CGNAT membuat satu IP publik mewakili banyak pelanggan, dan IP pool VPN berganti pemilik sehingga selalu dibatasi waktu.
- **Day 06:** di Linux, `auid` menyimpan identitas login asli setelah `sudo`. Di Entra ID, `notApplied` pada Conditional Access berarti tidak ada kebijakan yang dievaluasi, bukan diizinkan. Akun muncul sebagai nama pendek di Linux dan VPN, tetapi sebagai UPN di log cloud.
- **Day 07:** triage L1 berjalan dari mengambil alih, lima pertanyaan (siapa, apa, di mana, kapan, apakah wajar), enrichment, disposisi atau eskalasi, note, sampai handover. Disposisi dasarnya empat, dan ES 8.7 punya tujuh label bawaan. Undetermined tidak pernah ditutup tanpa alasan.
- **Day 08:** `chart` memilih dua sumbu, `timechart` selalu memakai waktu, dan keduanya memotong ke sepuluh seri dengan sisa menjadi OTHER. Grafik dipakai untuk melihat bentuk; angka untuk tiket diambil dengan `stats` dan rentang absolut.
- **Day 09:** report menjalankan aksi setiap kali jalan, alert hanya saat trigger cocok. Jendela waktu yang lebih pendek dari interval jadwal meninggalkan event yang tidak pernah dievaluasi. Throttle mencegah satu serangan menjadi puluhan notifikasi, dan objek milik akun yang dihapus menjadi yatim lalu berhenti jalan.

Day 10 merangkum fondasi ini.

### 1.2 SPL lanjutan dan knowledge object (Day 11-19)

- **Day 11:** `rex` dengan named capture group, `max_match=0` untuk multivalue, dan `mode=sed` yang hanya mengubah hasil. Di `eval`, kutip tunggal berarti nama field dan kutip ganda berarti string.
- **Day 12:** `foreach` dengan `'<<FIELD>>'` untuk nama field bertitik, `lookup` setelah `stats` dengan pilihan `OUTPUT` (menimpa) atau `OUTPUTNEW` (mengisi bila kosong), dan `makeresults` untuk menguji logika dengan kasus positif dan negatif sebelum menyentuh data nyata.
- **Day 13:** `transaction` dipilih bila ID dipakai ulang, ada penanda awal dan akhir, atau raw event dibutuhkan; selain itu `stats` lebih murah. `first()` dan `last()` mengikuti urutan pemrosesan, sedangkan `earliest()` dan `latest()` mengikuti waktu.
- **Day 14:** saring sedini mungkin, hindari `index=*`, wildcard di depan, dan negasi yang tidak perlu. `f!=x` hanya mengembalikan event yang punya `f`, sedangkan `NOT f=x` ikut mengembalikan event tanpa `f`. Perbaikan diukur di Job Inspector, dan versi sebelum dan sesudah harus menjawab pertanyaan yang sama.
- **Day 15:** Field Extractor punya lima langkah, metode regex dan delimiter, dan hasilnya disimpan sebagai `EXTRACT-` atau `REPORT-`. Objek private tidak terlihat orang lain tanpa pesan error.
- **Day 16:** field alias dan calculated field menyatukan nama field antar vendor. Urutan operasi search-time menentukan apa yang boleh memakai apa: field filter, extraction, `KV_MODE`, alias, calculated field, lookup, event type, lalu tag.
- **Day 17:** event type adalah kriteria search tanpa pipe dan subsearch yang menempel sebagai label, dan tag pada event type menentukan event mana yang masuk data model CIM.
- **Day 18:** macro adalah substitusi teks sebelum search jalan, bisa berargumen dan divalidasi, dan hasil ekspansinya dilihat dengan Control-Shift-E. Filter macro `<detection>_filter` adalah tempat pengecualian lokal.
- **Day 19:** workflow action GET, POST, dan Search mengubah satu klik menjadi pivot. GET ke layanan luar mengirim nilai field ke pihak ketiga, jadi field yang boleh dikirim dibatasi.

Day 20 merangkum Bagian B dan C.

### 1.3 Data model dan normalisasi (Day 21-28)

- **Day 21:** sumber data dipilih dari pertanyaan yang ingin dijawab, bukan dari volume. Sumber yang diam adalah temuan, karena setiap pertanyaan tentang rentang itu tidak bisa dijawab.
- **Day 22:** data model punya empat jenis dataset dan lima jenis attribute. Hanya root event, atau root search yang streaming, yang bisa diakselerasi. Pivot membaca field yang didefinisikan model saja.
- **Day 23:** CIM adalah kamus, bukan data. Event baru masuk data model bila rantainya utuh: event type, tag, nama field CIM, lalu nilai field yang benar.
- **Day 24:** `src`, `dest`, `user`, dan `action` adalah poros pivot lintas model, tetapi arti `src` dan `dest` berbeda per model, dan nilai `action` juga berbeda per model.
- **Day 25:** `tstats` membaca tsidx dan summary data model, bukan raw event. `summariesonly` default false; `true` lebih cepat tetapi bisa tidak lengkap. `prestats` dipakai sebelum `timechart`, dan `count(eval())` tidak bisa dipakai di `tstats`.
- **Day 26:** acceleration adalah sistem yang berjalan terus dan bisa gagal diam-diam. Asset & Identity menempelkan field seperti `src_priority` dan `user_category` berdasarkan `src`, `dest`, `dvc`, dan `user`, dan hanya selengkap lookup yang diisi.
- **Day 27:** SSE Data Inventory dan Detection Studio di ES 8.7 menilai data mana yang menopang konten mana. Detection ditulis di atas CIM karena nama sourcetype milik add-on bisa berubah.
- **Day 28:** kesalahan index-time permanen untuk data yang sudah masuk. Masking dengan `SEDCMD` hanya berlaku untuk data baru, `nullQueue` membuang event, dan routing memindahkannya ke index lain.

### 1.4 Konteks ancaman dan Enterprise Security (Day 29-36)

- **Day 29:** SOC adalah people, process, dan technology. Tier memisahkan kedalaman investigasi, sedangkan analyst, engineer, dan architect dibedakan oleh pertanyaan utamanya. Kontrol, standar, dan framework adalah tiga hal berbeda, dan risk score RBA bukan risk assessment organisasi.
- **Day 30:** attack vector menjawab jalan masuk, attack type menjawab tujuan. ATT&CK v19 punya 15 taktik setelah Defense Evasion dipecah menjadi Stealth (TA0005) dan Defense Impairment (TA0112). Detection menutup procedure, bukan technique, dan isi laporan intel dipilah ke empat tingkatan menurut pembacanya.
- **Day 31:** istilah ES 7 dan ES 8 dipetakan: notable event menjadi finding, risk notable tampil sebagai finding group, contributing events menjadi intermediate finding, risk object menjadi entity, threat object menjadi observable, dan Incident Review menjadi analyst queue.
- **Day 32:** dashboard Security posture, Executive summary, dan SOC operations dibaca untuk tujuan berbeda, dan setiap panelnya punya SPL yang bisa dibongkar.
- **Day 33:** Mission Control adalah tempat pekerjaan terjadi: investigation, note, response plan, disposition, dua jalur threat intelligence, dan annotations yang membuat rekap per framework mungkin. Indikator tanpa masa berlaku menghasilkan match yang menyesatkan.
- **Day 34:** continuous monitoring adalah proses, bukan layar. Lima tahap investigasi (Review events, Assessment, Determine risk, Mitigate, Re-assess) masing-masing punya hasil di tiket. Metrik waktu dilaporkan dengan median dan p90, dan dwell time dihitung per insiden dari temuan forensik.
- **Day 35:** RBA mengubah sinyal lemah menjadi skor per entity. Risk rule menulis intermediate finding ke index risk, risk factor memberi pengali dari konteks A&I, dan finding-based detection menghasilkan finding group. Score stacking dicegah dengan deduplikasi sebelum menjumlah.
- **Day 36:** detection event-based dibuat dengan output finding, intermediate finding, atau keduanya, dijadwalkan dengan jeda untuk data terlambat, disetel dengan throttling, filter, dan kalibrasi ambang, dan didokumentasikan dengan kartu detection.

Day 37 merangkum Bagian D, E, dan F.

### 1.5 Hunting (Day 38-40)

**Day 38, teknik hunting.** Hunting dimulai dari pertanyaan atau hipotesis, bukan dari alert, dan hasil paling berharganya adalah detection baru. Empat kategorinya mengikuti model Dragos: configuration (penyimpangan dari setelan baik), modeling (penyimpangan dari baseline), indicator (cocokkan artefak yang sudah dikenal), dan threat behavior (cara kerja penyerang). Matriks Robert M. Lee menyusunnya dua sumbu: environment atau threat, dan known atau unknown. Configuration dan modeling menuntut pengetahuan sistem, sehingga paling baik dikerjakan bersama pemilik sistem; indicator dan behavioral menuntut pengetahuan ancaman. Tidak ada satu kategori yang terbaik untuk semua lingkungan, dan modeling berasumsi baseline-nya bersih [S6]. Indicator ada di dasar Pyramid of Pain dan secara struktural tidak membantu korban pertama. Detection atomic memakai satu titik data, composite menggabungkan event yang jinak sendiri-sendiri, dan composite adalah pola yang sama dengan RBA. Contoh CRASHOVERRIDE menunjukkan keempat metode melihat serangan yang sama dari sudut berbeda.

**Day 39, long tail, outlier, dan PEAK.** Long tail memperlakukan data sebagai kategori: stack, hitung, lalu baca dari yang paling jarang (`rare` atau `stats count ... | sort count`). Outlier memperlakukan data sebagai angka: z-score, IQR atau persentil yang lebih tahan data condong, dan baseline per entity. `anomalydetection` punya metode histogram, zscore, dan iqr; aksi `remove` membuang outlier sehingga untuk hunting dipakai `annotate` atau versi `eventstats` [S1]. Beaconing dicari dari keteraturan interval: `streamstats` mengambil waktu koneksi sebelumnya, koefisien variasi mudah rusak oleh satu interval panjang, dan median dengan MAD lebih tahan. Keteraturan juga ciri forwarder, update checker, dan NTP, jadi ia penyaring, bukan bukti. PEAK punya tiga fase dengan lima langkah masing-masing [S2]:

| Fase | Langkah |
|---|---|
| Prepare | Select topic, research topic, generate hypothesis, scope hunt, plan |
| Execute | Gather data, pre-process data, analyze, refine hypothesis, escalate critical findings |
| Act | Preserve hunt, document findings, create detections, re-add topic to backlog, communicate findings |

Hasil "tidak ditemukan" sah bila scope dan celah datanya dicatat. Normalisasi path (huruf kecil, nama user dan nomor versi diganti penanda) memotong ekor palsu sebelum long tail dibaca.

**Day 40, menyimpan hasil.** Baseline, daftar normal yang sudah diverifikasi, dan pengetahuan "pernah terlihat atau tidak" hilang begitu jendela search ditutup, jadi disimpan di salah satu dari tiga wadah. Summary index untuk agregat historis, diisi dengan `collect`; bila akan diagregasi ulang ke periode lebih panjang, pakai `sistats` karena `dc()` dan `avg()` dari `stats` biasa tidak bisa dijumlahkan dengan benar [S12]. Rentang pengisi harus snapped dan jadwalnya diberi jeda terhadap ingest lag. Lookup KV store untuk tabel keadaan yang diperbarui per baris lewat `outputlookup append=true key_field=_key`, misalnya tabel first-seen dan allowlist dengan kolom `reason`, `owner`, dan `expires_at`. Metrics index untuk angka berkala yang tidak butuh konteks teks, dibaca dengan `mstats`. Summary tercemar oleh empat hal: data terlambat, pengisian ganda, baseline yang memuat insiden, dan skema yang berubah. First-seen dan baseline adalah alat prioritas, bukan bukti.

### 1.6 Respons dan otomasi (Day 41-42)

**Day 41, adaptive response.** AR adalah aksi yang dijalankan ES atas detection yang menyala (otomatis, diatur di detection editor) atau atas finding yang sedang dibaca analyst (ad hoc, dari Mission Control). ES 8.7 punya 13 AR bawaan, termasuk Finding, Nslookup, Ping, Run a script, dan Add Threat Intelligence [S4]. Containment yang sebenarnya, seperti isolasi host di EDR atau blokir di firewall, datang dari app AR vendor atau dari playbook. Keputusan otomatis atau tidak ditimbang dari empat faktor:

| Faktor | Pertanyaan |
|---|---|
| Keyakinan | Berapa FP rate detection itu menurut data disposisi, bukan menurut kesan |
| Reversibilitas | Bisa dibatalkan cepat, dan oleh siapa |
| Blast radius | Apa dampaknya bila salah sasaran, misalnya server kritis dibanding laptop |
| Kebijakan | Apakah butuh persetujuan lebih dulu |

Prinsipnya: otomatiskan enrichment secara luas, dan tindakan yang mengubah sistem secara sempit, dengan guardrail dari A&I dan batas jumlah aksi. Untuk ES di Splunk Cloud, relay heavy forwarder on-prem mengambil aksi yang diantrekan, sehingga tidak ada akses masuk baru ke jaringan internal; relay itu sendiri aset bernilai tinggi. Setiap eksekusi tercatat, secara klasik di index `cim_modactions` (cek di ES 8.7).

**Day 42, SOAR playbook.** Playbook mengotomasi alur multi-langkah dengan percabangan dan persetujuan; AR hanya satu aksi. Urutan yang aman: enrich, decide, approve, contain, notify, document, verify, dengan langkah yang mengubah sistem di balik prompt. Dari ES 8, playbook dipicu dengan empat cara: automation rules di Configure > Splunk SOAR > Automation rules, Run playbook manual dari tab Automation di Mission Control, response plan task, dan AR ke SOAR. Semuanya butuh pairing ES dengan SOAR. Satu detection hanya bisa terkait satu automation rule, satu rule boleh memuat beberapa playbook bertipe ES, dan eksekusi yang bersamaan berjalan FIFO [S3]. Playbook diuji dengan kasus bersih, kasus buruk, dan kasus gagal (layanan enrichment tidak menjawab tidak sama dengan bersih). SOAR On-premises 8.6.0 adalah rilis terakhir yang mendukung Python 3.9, sehingga otomasi yang belum dimigrasi ke Python 3.13 bisa berhenti setelah upgrade tanpa perubahan apa pun di sisi ES [S5].

### 1.7 Platform (Day 43-45)

**Day 43, arsitektur dan operasi.** Setiap kesimpulan bertumpu pada tiga asumsi: datanya ada, search terjadwal benar-benar jalan, dan hasilnya lengkap. Bucket bergerak dari hot, warm, cold, sampai frozen, dan menjadi frozen karena usia (`frozenTimePeriodInSecs`) atau ukuran total index (`maxTotalDataSizeMB`), mana yang tercapai lebih dulu [S11]. Batas nyata hunting dibaca dari `dbinspect`, bukan dari kebijakan tertulis. Replication factor adalah jumlah salinan raw, search factor jumlah salinan yang bisa langsung dicari, dan cluster yang sedang fixup bisa memberi jumlah event berbeda pada dua kali menjalankan search yang sama. Scheduler yang penuh menunda (deferred) atau melewatkan (skipped); skipped berarti eksekusi itu hilang selamanya dan hanya terlihat di `index=_internal sourcetype=scheduler`. Biaya ingest dinilai sebagai gigabyte per detection yang masih jalan. Sebelum menulis "tidak ada bukti", cek empat hal: peringatan hasil tidak lengkap, `scanCount`, batas retensi, dan status summary bila memakai `summariesonly=true`.

**Day 44, RBAC dan data sensitif.** Akses ditentukan empat lapis: authentication, role, capability, dan izin index serta knowledge object. Izin bersifat akumulatif, jadi membatasi berarti mencabut role yang luas. Batas yang paling kuat adalah index terpisah lewat `srchIndexesAllowed`. `srchFilter` menyaring event, bukan field, dan bisa bocor lewat `tstats`, summary index, dan lookup. Field filter di Splunk Enterprise 10.6 menyamarkan field saat search dengan menghapus, mengganti string, atau hash, dengan pengecualian per role; lookup tidak terlindungi dan `tstats` hanya mematuhi filter pada indexed field [S7]. Setiap `outputlookup` atau `collect` membuat salinan data dengan model izin baru. Akses sementara untuk insiden butuh jalur resmi berkedaluwarsa, karena kontrol yang membuat pekerjaan mustahil akan diakali.

**Day 45, sumber konten.** research.splunk.com adalah katalog konten Splunk Threat Research Team, dengan ESCU v6.7.0 sebagai rilis terbaru saat diakses [S8], dan ESCU adalah paket app konten yang sama untuk ES. SSE mencocokkan data yang kamu punya dengan konten yang bisa jalan; SSE 3.7.1 ke bawah tidak bisa memperbarui konten melewati ESCU 4.22.0 [S9]. Lantern berisi panduan cara, bukan detection. Content management ES adalah tempat detection dikelola. Detection vendor dinilai sebelum diaktifkan: baca how to implement, buktikan data model terisi, cek macro dan lookup, jalankan manual tujuh hari, baca known false positives, lalu tuning lewat filter macro, bukan logika inti. Detection aktif di atas data model kosong tampak hijau dan tidak pernah menyala.

### 1.8 Sintesis (Day 46)

Tiga studi kasus PT JAB berbagi satu gagasan: pemicu hampir tidak pernah membuktikan keberhasilan serangan, dan bukti keberhasilan ada di sudut lain. Investigasi berputar di empat sudut (identitas, aset, jaringan, eksekusi) yang tidak punya urutan tetap, dan bila tiga query di satu sudut tidak memberi kemajuan, pindah sudut. Enam pertanyaan dipakai berurutan: apa yang sebenarnya terjadi, kapan pertama kali (T0), siapa dan apa yang terlibat, berhasil atau tidak, apa yang terjadi setelahnya, dan apa yang belum bisa dilihat.

Tabel berikut merangkum ketiga kasus; cari kolom terakhir, karena keterbatasan data yang menentukan kalimat kesimpulan di setiap kasus.

| Kasus | Pemicu | Bukti keberhasilan | Lingkup | Keterbatasan |
|---|---|---|---|---|
| SOC-2026-0281, phishing | Laporan pengguna | Login sukses `andi.pratama` dari 203.0.113.50 tak lama setelah klik | 14 penerima | Proxy tidak mencatat user |
| SOC-2026-0282, webshell di `jkt-portal01` | Alert IDS | Proses anak web server (`sh`, `curl` sebagai `www-data`) dari auditd | Seluruh direktori unggahan | Tidak ada EDR; access log hanya 7 hari |
| SOC-2026-0283, `svc_backup` | Finding dari baseline login | Service baru di `JKT-FS01`, arsip 340 MB | Host berantai dari `JKT-WS-0388` | Agent `JKT-DB02` mati empat jam |

Setiap kasus ditutup dengan satu detection baru, dan dua dari tiganya memakai tabel first-seen dari Day 40.

### 1.9 Peta konsep dan jejak SOC-2026-0283

Peta berikut menggabungkan diagram Day 01-46 dalam satu gambar. Pakai sebagai satu-satunya bantuan saat mengerjakan Bagian C di bagian 2-4.

```
 A FONDASI (01-09)    index | sourcetype | _time vs _indextime | log Windows, Sysmon, jaringan, Linux, cloud
        |             SPL inti -> triage L1 + disposisi -> chart/timechart -> report, alert, dashboard
        v
 B SPL LANJUTAN (11-14)   rex/eval | foreach/lookup/makeresults | transaction vs stats | search efisien
 C KNOWLEDGE OBJECT (15-19) extraction -> alias/calculated -> event type -> tag | macro | workflow action
        v
 D DATA MODEL (21-28) sumber data -> data model/Pivot -> CIM (tag + field + nilai) -> field poros
        |             -> tstats -> acceleration + A&I -> SSE/Detection Studio -> onboarding index-time
        v
 E KONTEKS (29-30)    peran SOC, framework, risiko | ATT&CK v19, TTP, tingkatan intel
        v
 F ES (31-36)         finding/entity/observable -> dashboard -> Mission Control + intel + annotation
        |             -> lima tahap + metrik -> RBA -> detection (event-based, finding-based)
        |                      ^
        v                      | Act: create detections
 G HUNTING (38-40)    4 kategori -> long tail/outlier/beacon (PEAK) -> simpan: summary, KV store, metrics
        v
 H RESPONS (41-42)    AR: satu aksi (otomatis/ad hoc, guardrail) | SOAR: alur + persetujuan + dokumentasi
        v
 I PLATFORM (43-45)   cakupan nyata (retensi, cluster, scheduler) | akses (index, srchFilter, field filter) | konten siap pakai
        v
 J SINTESIS (46)      empat sudut + enam pertanyaan -> kesimpulan + keyakinan + keterbatasan -> detection baru
```

Cara membaca peta: setiap kotak punya artefak yang bisa diperiksa (query, konfigurasi, tiket, laporan). Bila sebuah kesimpulan gagal dipertahankan, telusuri ke atas sampai menemukan kotak yang artefaknya hilang atau lemah.

Tabel berikut menjawab enam pertanyaan SOC lead di bagian Ide inti dengan artefak fiktif PT JAB. Baca per baris; kolom terakhir adalah mata rantai yang paling mudah putus di baris itu.

| Pertanyaan | Jawaban untuk SOC-2026-0283 | Day asal | Mata rantai yang paling mudah putus |
|---|---|---|---|
| 1 Data dan kelengkapannya | `wineventlog` (4624, 7045, 4697, 4698), data model Authentication dan Endpoint, Network_Traffic dengan IP `JKT-FS01` 10.20.10.21 dan `JKT-DB02` 10.20.10.32 | Day 03, Day 46 bagian 2.3 | Kelengkapan baru terbukti setelah cek hari tanpa data, retensi nyata, dan status input (Day 43 bagian 2.6) |
| 2 Query yang bisa dipindahkan | Query memakai field CIM dengan `summariesonly=false`; event masuk Authentication karena event type dan tag `authentication` | Day 17 bagian 1.7, Day 25 bagian 1.3 | Tag yang hilang membuat event tidak ada di data model tanpa pesan error |
| 3 Kenapa sinyal muncul | Baseline login per jam di summary index menandai `svc_backup` login jam 03 jauh di atas pola biasanya; konteks identitas dari A&I dibaca lebih dulu | Day 40 bagian 2.1, Day 46 bagian 2.3 langkah C1 | Baseline yang memuat insiden atau jam yang bolong (Day 40 bagian 1.7) |
| 4 Jalannya investigasi | Rantai `JKT-WS-0388` ke `JKT-FS01` ke `JKT-DB02`, percobaan gagal ke `JKT-APP03`; pindah dari sudut identitas ke eksekusi di host tujuan | Day 46 bagian 1.1 dan 2.3, Day 34 bagian 1.3 | Berputar di sudut autentikasi saja dan tidak pernah membuktikan eksekusi |
| 5 Tindakan | Rotasi kredensial, isolasi `JKT-WS-0388` dan `JKT-FS01`, akuisisi forensik; isolasi server berdampak tinggi, jadi menurut matriks keputusan ia ad hoc atau lewat playbook dengan persetujuan | Day 46 bagian 2.3, Day 41 bagian 1.2, Day 42 bagian 1.4 | Containment otomatis dari detection yang FP rate-nya belum diukur |
| 6 Yang tidak terlihat dan yang lahir | Aktivitas di `JKT-DB02` tidak bisa dipastikan selama agent mati; detection baru: akun layanan login ke host yang tidak pernah dipakainya dalam 30 hari | Day 46 bagian 2.3, Day 40 bagian 1.4 | Hasil kosong ditulis sebagai "tidak ada aktivitas" padahal tidak ada data |

Jawaban untuk pertanyaan "mata rantai mana yang paling lemah" di kasus ini adalah baris 6: satu agent yang mati membuat satu host tidak bisa dinilai sama sekali, dan kelemahan itu baru terlihat karena pertanyaan keenam ditanyakan. Baris 3 menunjukkan hal lain yang menarik: pemicunya sendiri adalah artefak hunting. Baseline yang disimpan di Day 40 menjadi sumber finding, sehingga Bagian G bukan pekerjaan sampingan, tetapi salah satu jalur masuk ke antrean.

### 1.10 Glosarium

Definisi di bawah ditulis dengan kata sendiri untuk keperluan belajar. Kolom terakhir adalah pasangan yang paling sering membuat jawaban interview keliru.

| Istilah | Penjelasan singkat | Sering tertukar dengan |
|---|---|---|
| `_indextime` | Waktu event masuk Splunk; selisihnya dengan `_time` adalah ingest lag | `_time`, waktu kejadian |
| `first()` / `last()` | Nilai dari event pertama atau terakhir yang diproses; default event terbaru diproses lebih dulu | `earliest()` / `latest()`, urutan waktu |
| `OUTPUTNEW` | Lookup hanya mengisi field yang masih kosong | `OUTPUT`, yang menimpa |
| Calculated field | Ekspresi eval yang dihitung setiap search pada sourcetype tertentu | Field alias, yang hanya memberi nama lain |
| Tag | Label kategori yang menentukan event masuk data model CIM | Event type, kriteria search yang menjadi label |
| Filter macro | Macro `<detection>_filter` tempat pengecualian lokal tanpa mengubah logika inti | Mengedit search inti detection vendor |
| CIM | Kamus nama field, tag, dan nilai yang diharapkan | Add-on vendor yang benar-benar menormalisasi |
| `summariesonly` | Bila true, `tstats` hanya membaca summary terakselerasi | Jaminan hasil lengkap |
| Data model acceleration | Summary tsidx per data model untuk `tstats` | Summary index, yang diisi sendiri dengan `collect` |
| Finding | Item di analyst queue (dulu notable event) | Intermediate finding, yang tidak masuk antrean |
| Finding group | Kumpulan finding per entity dari finding-based detection | Investigation, wadah kerja yang dikelola manusia |
| Entity | Subjek yang diberi skor risiko (user atau system) | Observable, artefak tanpa skor |
| Disposition | Kesimpulan tentang benar tidaknya detection dan aktivitasnya | Status, posisi kasus di alur kerja |
| Risk score RBA | Akumulasi bobot sinyal per entity | Risk assessment organisasi |
| Long tail | Nilai kategori paling jarang setelah stacking | Outlier, nilai numerik yang ekstrem |
| Jitter | Variasi interval antar koneksi; koefisien variasi atau MAD dibagi median | Bukti C2, padahal forwarder dan NTP juga teratur |
| Composite detection | Gabungan event yang jinak sendiri-sendiri | Atomic, satu titik data |
| `sistats` | Mengisi summary dalam bentuk antara yang bisa diagregasi ulang | `stats`, yang hasilnya tidak bisa dijumlahkan untuk `dc()` |
| KV store lookup | Tabel ber-`_key` yang diperbarui per baris | Lookup CSV, yang ditulis ulang seluruhnya |
| Adaptive response | Satu aksi dari detection (otomatis) atau dari finding (ad hoc) | SOAR playbook, alur multi-langkah |
| Automation rule | Aturan ES yang menjalankan playbook saat detection tertentu menghasilkan finding; satu detection, satu rule | Beberapa rule per detection |
| AR relay | Heavy forwarder on-prem yang mengambil aksi yang diantrekan ES di Cloud | Membuka akses masuk ke jaringan internal |
| Skipped | Eksekusi scheduled search yang hilang selamanya | Deferred, yang hanya tertunda |
| Search factor | Jumlah salinan bucket yang bisa langsung dicari | Replication factor, jumlah salinan raw |
| `srchFilter` | Filter event yang dipaksakan ke setiap search sebuah role | Batas keamanan yang kuat, yaitu index terpisah |
| Field filter | Penyamaran field saat search per role (hapus, string, hash) | Masking index-time yang permanen |
| ESCU | Paket app konten Splunk Threat Research Team untuk ES | Lantern, yang berisi panduan cara |
| Empat sudut pivot | Identitas, aset, jaringan, eksekusi yang saling menguatkan | Urutan wajib seperti lapisan jaringan |

## 2-4. Lab gabungan dan troubleshooting

Lab ini dibagi empat. Bagian A melatih keputusan lewat skenario dengan pembahasan, Bagian B menjalankan satu hunt dari hipotesis sampai respons dengan semua command inti, Bagian C mengulang penelusuran bagian 1.9 untuk kasus lain, dan Bagian D menutup seluruh topik dengan rencana memperkuat kelemahan. Semua skenario fiktif, dan semua perintah dijalankan di VM lab terisolasi.

### Bagian A: latihan skenario dengan pembahasan

Jawab dulu, baru baca pembahasannya.

**Skenario 1: query hunting yang lambat.** Hunt long tail proses berjalan 14 menit:

```
index=* sourcetype=*sysmon* EventCode=1 | stats count dc(host) AS hosts BY Image | where hosts<=2
```

Apa yang diperbaiki tanpa mengubah pertanyaannya?

Pembahasan: `index=*` memaksa Splunk memeriksa semua index, dan wildcard di sourcetype mencegah pemangkasan awal (Day 14 bagian 1.2 dan 1.3). Sebut index dan sourcetype persis; di PT JAB itu `index=sysmon`. Bila data model Endpoint.Processes terakselerasi, versi `tstats ... by Processes.process_path` jauh lebih cepat (Day 25), tetapi pastikan `summariesonly=false` atau rentang waktunya tercakup summary, agar hasilnya sama. Bandingkan scanCount dan waktu di Job Inspector sebelum dan sesudah; jumlah baris hasil harus sama.

**Skenario 2: beacon yang tidak terlihat.** Hunt beaconing Day 39 bagian 2.4 tidak menemukan apa pun, padahal tim jaringan yakin ada host yang menghubungi tujuan aneh setiap lima menit. Apa saja kemungkinannya?

Pembahasan: (a) sumber data berupa flow teragregasi per beberapa menit, sehingga interval asli hilang; (b) beacon memakai jitter besar, sehingga koefisien variasi di atas ambang; pakai versi median dan MAD; (c) `dest_port` difilter 443 padahal beacon memakai port lain; (d) rentang 24 jam hanya memuat sedikit koneksi bila beacon tidur di malam hari. Catat mana yang benar, karena "tidak ditemukan" hanya sah bila celah datanya ditulis.

**Skenario 3: otomasi atau tidak.** Detection "Encoded PowerShell" punya FP rate 35% (sebagian besar skrip admin). Pimpinan ingin isolasi host otomatis. Apa rekomendasimu?

Pembahasan: dengan keyakinan sedang dan blast radius tinggi, matriks Day 41 bagian 1.2 menyarankan enrichment otomatis dan tindakan ad hoc atau lewat SOAR dengan persetujuan. Langkah realistis: turunkan detection ke output intermediate finding, tambah allowlist sempit untuk skrip admin yang dikenal, dan biarkan finding group RBA yang memicu playbook dengan prompt persetujuan.

**Skenario 4: `first` atau `earliest`.** Laporan menyebut "login pertama penyerang pukul 02.14" berdasarkan `stats first(_time)`. Kenapa itu berisiko?

Pembahasan: `first()` mengembalikan nilai dari event pertama yang diproses, dan secara default Splunk mengembalikan event terbaru lebih dulu, sehingga `first(_time)` biasanya adalah waktu terakhir, bukan pertama (Day 13 bagian 1.4). Untuk waktu paling awal, pakai `earliest(_time)` atau `min(_time)`.

**Skenario 5: detection yang diam.** Setelah alert L1 PT JAB dipindah ke ES, detection `JAB - Login berhasil setelah rangkaian gagal` tidak menghasilkan finding selama tiga hari, padahal search yang sama dijalankan manual memberi hasil. Apa yang dicek lebih dulu?

Pembahasan: hasil manual yang benar mengesampingkan logika, jadi pertanyaannya apakah eksekusi terjadwal pernah terjadi. Cek `index=_internal sourcetype=scheduler` untuk nama detection itu, lalu bandingkan `run_time` rata-ratanya dengan interval jadwal (Day 43 bagian 2.2). Bila search memakai data model, cek juga status acceleration di search head ES yang baru, karena summary di sana bisa belum selesai dibangun (Day 26 bagian 2.1).

**Skenario 6: baseline yang dibagikan.** Seorang engineer membuat tabel first-seen dari `wineventlog` dan membagikan lookup KV store-nya ke semua app supaya dashboard NOC bisa memakainya. Apa masalahnya?

Pembahasan: lookup adalah salinan data dengan model izin baru, dan field filter tidak melindungi lookup, sehingga orang yang tidak punya akses ke `wineventlog` bisa membaca isinya (Day 44 bagian 1.4 dan 1.6). Cari saved search yang menulis `outputlookup` atau `collect` dengan sharing lebih luas daripada index sumbernya (Day 44 bagian 2.5), lalu persempit sharing lookup itu.

### Bagian B: lab gabungan, dari hipotesis sampai respons

**Tujuan:** satu hunt end-to-end di lab yang memakai semua command inti SPL, menyimpan hasilnya, membuktikan cakupannya, dan menutupnya dengan detection serta respons.

1. **Prepare (PEAK):** hipotesis "Ada host lab yang menjalankan PowerShell terenkode lalu berkomunikasi berkala ke tujuan yang jarang".
2. **Uji logika dulu (`makeresults`, Day 12):** buat 5 baris CommandLine (positif/negatif). Uji `rex` + `eval` yang mengekstrak blob base64 dan menandai `-enc`.
3. **Cari proses (tstats + foreach, Day 25/12):**
   ```
   | tstats summariesonly=false count values(Processes.process) AS cmd from datamodel=Endpoint.Processes
       where Processes.process_name="powershell.exe" earliest=-7d by Processes.dest Processes.user
   | foreach Processes.* [eval <<MATCHSTR>>='<<FIELD>>']
   | fields - Processes.*
   | mvexpand cmd
   | rex field=cmd "(?i)\s[-/](?:ec|e[a-z]*)\s+(?<blob>[A-Za-z0-9+/=]{20,})"
   | where isnotnull(blob)
   | eval blob_len=len(blob)
   | stats count max(blob_len) AS max_len BY dest user
   ```
   `cmd` adalah field multivalue dari `values()`, karena itu dipecah dengan `mvexpand` sebelum `rex`.
4. **Cari komunikasi berkala dari host itu (outlier/beacon, Day 39):** jalankan Day 39 bagian 2.4 untuk `src` = host temuan.
5. **Rare destination (long tail, Day 39):** `| tstats count dc(All_Traffic.src) AS srcs from datamodel=Network_Traffic.All_Traffic by All_Traffic.dest | where srcs=1 | sort count`.
6. **Konteks (lookup, Day 12/26):** enrichment `dest_priority`/owner setelah `stats`.
7. **Sesi (transaction vs stats, Day 13):** bangun sesi koneksi dari host ke tujuan dengan `transaction ... maxpause=5m`, lalu versi `stats`. Bandingkan dengan Job Inspector (Day 14).
8. **Timeline:** `earliest`/`latest` per tahap (bukan `first`/`last`).
9. **Simpan (Day 40):** masukkan pasangan host dan proses dari langkah 3 ke tabel first-seen KV store dengan pola Day 40 bagian 2.3, lalu jalankan ulang besoknya dan buktikan `first_seen` tidak bergeser maju.
10. **Buktikan cakupan (Day 43):** jalankan tiga search pembuktian Day 43 bagian 2.6 untuk index yang dipakai langkah 3 sampai 5, lalu tulis satu kalimat keterbatasan.
11. **Bandingkan dengan konten siap pakai (Day 45):** cari satu detection ESCU untuk PowerShell terenkode di research.splunk.com, lalu nilai prasyaratnya dengan alur Day 45 bagian 2.1. Catat apakah detection-mu menambah sesuatu yang tidak dicakup konten itu.
12. **Act:** dokumentasikan hasil (ditemukan / tidak / data kurang). Buat detection composite dengan output intermediate finding (Day 35-36).
13. **Respons:** AR Nslookup otomatis + playbook Shuffle/SOAR dengan approval (Day 41-42).

**Data uji:** di VM Windows lab, jalankan PowerShell terenkode yang jinak (`Get-Date`) dan loop koneksi berkala ke server web lab (Day 39 bagian 3).

### Bagian C: menelusuri satu kasus dari ujung ke ujung

Pilih SOC-2026-0281 atau SOC-2026-0282 dari Day 46 bagian 2.1 atau 2.2. Isi tabel dengan enam baris yang sama seperti tabel bagian 1.9:

```
Pertanyaan | Jawaban untuk kasus itu | Day asal | Mata rantai yang paling mudah putus
```

Untuk setiap baris, tunjuk artefak yang bisa diperiksa: query, konfigurasi, atau bagian laporan. Baris yang tidak bisa diisi adalah temuanmu sendiri. Lalu jawab pertanyaan SOC lead dalam satu paragraf: mata rantai mana yang paling lemah di kasus itu, dan apa satu perubahan yang paling murah untuk menguatkannya.

### Bagian D: rencana memperkuat kelemahan

Isi kolom keyakinan (1 = sangat lemah, 5 = sangat yakin) setelah mencoba menjelaskan ulang setiap topik tanpa melihat catatan. Tabel ini template, jadi ganti dengan penilaian sendiri. Kolom terakhir menyebut bukti yang membuat sebuah topik boleh dianggap kuat.

| Topik | Keyakinan (1-5) | Cara memperkuat | Bukti bahwa sudah kuat |
|---|---|---|---|
| Index, sourcetype, waktu, job | _ | Ukur ingest lag per sourcetype di lab (Day 01 bagian 2.2) | p95 lag per sourcetype tercatat |
| SPL inti dan triage L1 | _ | Dua filter yang terlihat sama (Day 02 bagian 2.2); note tiket SOC-2026-0217 (Day 07 bagian 2.6) | Satu note lengkap dengan query, rentang, dan angka |
| Disposisi | _ | Delapan skenario disposisi di lab Day 07 bagian 3 dengan tujuh label ES 8.7 (Day 07 bagian 1.5) | Delapan skenario dengan alasan dan pemilik tindak lanjut |
| Log Windows, Sysmon, PowerShell | _ | Satu sesi 4624, 4672, dan proses (Day 03 bagian 2.5); process tree (Day 04 bagian 2.3) | Satu linimasa lab dari logon sampai proses |
| Log jaringan, Linux, cloud | _ | Kronologi gabungan VPN (Day 05 bagian 2.7) dan linimasa Day 06 bagian 2.9 | Satu linimasa lintas tiga sumber dengan akun yang diseragamkan |
| Visualisasi, report, alert | _ | Batas sepuluh seri (Day 08 bagian 1.5); jadwal dan rentang alert (Day 09 bagian 2.2) | Satu alert tanpa gap dan tanpa duplikat, dengan throttle |
| `rex`, `eval`, `foreach`, `lookup`, `makeresults` | _ | Uji `makeresults` positif dan negatif (Day 12 bagian 2.5) | Minimal dua kasus positif dan dua negatif lolos |
| `transaction` dan first/last | _ | Day 13 bagian 2.4; ulangi Skenario 4 di Bagian A | Satu query yang menampilkan keduanya dan selisihnya dijelaskan |
| Search efisien | _ | Tiga pasangan sebelum/sesudah (Day 14 bagian 2.1) | Angka Job Inspector dan jumlah baris hasil yang sama |
| Knowledge object | _ | Satu detection untuk empat sumber (Day 17 bagian 2.5); macro filter (Day 18 bagian 2.7); workflow action Search (Day 19 bagian 2.3) | Detection jalan di semua sumber tanpa `OR` per vendor |
| Data model, CIM, field CIM | _ | Normalisasi RADIUS ke Authentication (Day 23 bagian 2.4); pivot satu IP lintas model (Day 24 bagian 2.1) | Event RADIUS muncul di data model dengan nilai `action` baku |
| `tstats`, acceleration, A&I | _ | Validasi data model (Day 25 bagian 2.4); cakupan A&I (Day 26 bagian 2.4) | Persentase entitas tak dikenal tercatat |
| SSE dan onboarding | _ | Matriks data, content, dan celah (Day 27 bagian 2.4); uji onboarding tanpa menyentuh index produksi (Day 28 bagian 2.2) | Matriks terisi dan satu sourcetype ter-onboard dengan timestamp benar |
| SOC, peran, framework, risiko | _ | Jelaskan tier dan peran lisan dua menit (Day 29 bagian 1.2 dan 1.3); matriks risiko (Day 29 bagian 2.6) | Rekaman penjelasan lisan |
| Serangan, ATT&CK, TTP, intel | _ | Halaman T1053.005 (Day 30 bagian 1.6); pecah satu laporan publik ke empat tingkatan (Day 30 bagian 1.9) | Satu laporan terpilah dan dua procedure teruji |
| Istilah dan dashboard ES | _ | Kartu ES 7 ke ES 8 (Day 31 bagian 1.2); tabel tugas ke dashboard (Day 32 bagian 1.1) | Kartu dua arah tanpa melihat catatan |
| Mission Control, intel, annotation | _ | Response plan akun terkompromi (Day 33 bagian 2.5); annotation pada event risiko (Day 33 bagian 2.8) | Satu investigation lab tertutup dengan disposition |
| Lima tahap dan metrik | _ | Kasus lab lima tahap (Day 34 bagian 2.1 sampai 2.5); MTTA, MTTR, dan dwell time (Day 34 bagian 2.6 dan 2.7) | Median dan p90 dari data lab dengan definisi titik awal |
| RBA dan detection | _ | RBA mini (Day 35 bagian 2.5) dan detection lengkap (Day 36 bagian 2.1) | Satu finding group dari tiga risk rule kecil |
| Teknik hunting | _ | Satu hunt per kategori (Day 38 bagian 3) | Empat hunt tercatat dengan kelemahannya |
| Long tail, outlier, PEAK | _ | Hunt PEAK lengkap 15 langkah (Day 39 bagian 2.5 dan 3) | Laporan hunt termasuk hasil "tidak ditemukan" bila itu hasilnya |
| Summary index, KV store, metrics | _ | First-seen (Day 40 bagian 2.3) dan allowlist berkedaluwarsa (Day 40 bagian 2.4) | `first_seen` tidak bergeser setelah tiga hari |
| Adaptive response | _ | Matriks AR untuk tiga detection (Day 41 bagian 2.4) | Paragraf guardrail tertulis |
| SOAR | _ | Playbook tiga cabang (Day 42 bagian 3); empat kasus uji phishing (Day 42 bagian 2.5) | Cabang gagal enrichment terbukti tidak menutup kasus |
| Arsitektur dan operasi | _ | Peta retensi nyata (Day 43 bagian 2.1); alert skipped search (Day 43 bagian 3) | Tabel tanggal tertua per index |
| RBAC dan data sensitif | _ | Tiga uji jalur `srchFilter` (Day 44 bagian 2.2); deteksi kebocoran lookup (Day 44 bagian 2.5) | Daftar jalur yang bocor di lab |
| Konten siap pakai | _ | Nilai satu detection ESCU (Day 45 bagian 2.1) | Satu detection dengan prasyarat terbukti dan known FP dibandingkan |
| Studi kasus | _ | Tiga laporan satu halaman (Day 46 bagian 3) dan Bagian C di atas | Tiga laporan dengan keterbatasan dan satu detection baru masing-masing |

**Aturan rencana:**
- Kerjakan dulu topik yang paling sering dipakai di pekerjaan (SPL, CIM dan data model, detection, investigasi) dengan keyakinan 3 ke bawah.
- Untuk hal yang bergantung versi (ES 7 vs ES 8, ATT&CK v19), siapkan penjelasan dua versi karena dokumentasi lama masih beredar.
- Satu topik dianggap kuat bila kamu bisa menjelaskannya lisan dua menit dan menunjukkan satu bukti dari lab (query, angka Job Inspector, atau screenshot catatan sendiri).

**Hasil yang sebaiknya tersimpan:**
- Jawaban tertulis enam skenario Bagian A, dengan catatan mana yang salah pada percobaan pertama.
- Uji `makeresults` dengan minimal dua kasus positif dan dua negatif, beserta hasilnya.
- Query langkah 3-5 Bagian B dengan angka Job Inspector (waktu dan scanCount).
- Perbandingan `transaction` dan `stats` di langkah 7: jumlah sesi dan waktu eksekusi.
- Tabel first-seen dan satu kalimat keterbatasan dari langkah 9 dan 10.
- Laporan hunt singkat dengan hasil (ditemukan, tidak ditemukan, atau data kurang) dan detection yang lahir dari hunt.
- Tabel enam baris Bagian C untuk satu kasus Day 46.
- Tabel Bagian D yang sudah diisi penilaian sendiri.

### Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| `foreach` gagal | Kutip pada nama field bertitik | Pakai `'<<FIELD>>'` (Day 12) |
| `rex` tidak cocok | Regex belum diuji dengan variasi | Uji di `makeresults` dengan kasus positif dan negatif |
| Beacon tidak muncul | Sumber data berupa flow agregat; jitter tinggi | Pakai sumber per koneksi; versi median dan MAD (Day 39 bagian 2.4) |
| Lambat | Filter awal lemah atau rentang terlalu lebar | Perbaiki filter awal dan rentang waktu (Day 14) |
| `tstats` dan search biasa memberi angka berbeda | `summariesonly=true` atau summary belum lengkap | Jalankan dengan `summariesonly=false`; cek status acceleration (Day 26 bagian 2.1) |
| Data model kosong padahal index penuh | Tag atau event type tidak ada | `stats count BY tag eventtype` pada sourcetype itu (Day 23 bagian 2.1) |
| Tabel first-seen berisi baris ganda | `key_field` tidak diset atau `_key` tidak unik | `\| inputlookup <lookup> \| stats count BY entity \| where count>1` (Day 40) |
| Detection tidak pernah fire | Skipped search, bukan logika | `index=_internal sourcetype=scheduler` (Day 43 bagian 2.2) |
| Hunting data lama kosong | Bucket sudah frozen karena usia atau ukuran | `dbinspect` untuk tanggal tertua (Day 43 bagian 2.1) |
| Playbook tidak muncul di automation rule | Bukan tipe ES, atau detection sudah terkait rule lain | Day 42 bagian 4 |

## 5. Kesalahan umum dan jebakan

- `first()` dipakai untuk "pertama kali" padahal yang dimaksud urutan waktu (Day 13).
- `summariesonly=true` saat hunting historis, sehingga data yang belum ter-summarize hilang (Day 25).
- `rex` dijalankan di `_raw` padahal field sudah ada; kutip tunggal dan ganda tertukar di `eval` (Day 11).
- `lookup` dipanggil sebelum `stats`; `OUTPUT` menimpa field CIM yang sudah benar (Day 12).
- `NOT` dan `!=` dianggap sama (Day 14).
- Mengira data model terisi karena index-nya penuh, padahal tag atau event type yang menjadi constraint tidak ada (Day 17 dan Day 23).
- Menganggap langka berarti jahat, atau memakai baseline yang sudah tercemar aktivitas penyerang (Day 38-39).
- Menyimpan summary dengan `stats` lalu menjumlahkan `dc()` ke periode lebih panjang (Day 40).
- Containment otomatis dipasang pada detection yang masih tinggi false positive (Day 41).
- Lupa pairing ES dan SOAR; mengira satu detection bisa punya banyak automation rule (Day 42).
- Menulis "tidak ada bukti" tanpa memeriksa retensi nyata, kesehatan cluster, dan skipped search (Day 43).
- Mengandalkan `srchFilter` sebagai batas keamanan, atau lupa bahwa lookup dan summary index adalah salinan data dengan izin baru (Day 44).
- Melaporkan jumlah detection yang diaktifkan sebagai cakupan (Day 45).
- Berhenti pada pemicu, atau menyimpulkan keberhasilan dari alert pencegahan (Day 46).

## 6. Catatan terkini

Bagian ini mengumpulkan detail versi dan perubahan yang dicatat di Day asal. Tidak mengubah isi review, tetapi menjelaskan kenapa dokumentasi dan materi lama bisa berbeda dengan catatan ini.

- **SPL 10.x:** `foreach` mendukung mode multivalue/json_array; `makeresults` mendukung `format=csv|json data=`; Evaluation functions punya kategori JSON (Day 11-12).
- **ES 8.7:** Detection Studio, 13 AR bawaan, automation rules (Configure > Splunk SOAR), Run playbook dari Mission Control (Day 27, 41, dan 42).
- SOAR On-prem 8.6.0 (Agu 2026) adalah rilis terakhir dengan Python 3.9; otomasi perlu dimigrasi ke Python 3.13 (Day 42) [S5].
- Splunk Enterprise 10.6 memuat field filter untuk menyamarkan field per role saat search, sehingga materi lama yang menyebut Splunk tidak punya kontrol tingkat field tidak berlaku lagi untuk versi ini (Day 44) [S7].
- research.splunk.com menyebut ESCU v6.7.0 sebagai rilis terbaru saat diakses, dan SSE 3.8.3 adalah versi default (Day 45) [S8] [S9].
- Dragos menerbitkan ulang kerangka empat tipe deteksi untuk OT pada September 2025, termasuk konsep atomic dan composite (Day 38) [S6].
- Survei SANS 2026 Threat Hunting yang dikutip di Day 39 menyebut hanya 37% organisasi punya metodologi hunting yang didefinisikan formal, turun dari 46% pada 2025 [S10]. Angkanya dari siaran pers.
- ATT&CK v19 memecah Defense Evasion menjadi Stealth dan Defense Impairment, sehingga pemetaan di laporan dan detection lama perlu disesuaikan (Day 30).

## 7. Cheat sheet

```
FONDASI   index | sourcetype | rentang | mode ; lag = _indextime - _time ; dataset statis = rentang absolut
          search (tidak peka huruf) vs where (peka) ; NOT f=* (tanpa f) vs f!=* (kosong)
TRIAGE    5 tanya -> enrichment -> disposisi (7 label ES 8.7) / eskalasi -> note -> handover
SPL  | tstats [summariesonly prestats fillnull_value] fn from datamodel=DM.Root where .. by .. [span]
     | transaction ids maxspan maxpause startswith endswith  (vs stats range(_time) BY id)
     first/last = urutan ; earliest/latest = waktu
     | rex field=F "(?<x>re)" [max_match=0] | rex mode=sed "s/a/b/g" ; | eval ' '=field " "=string
     | foreach X.* [eval <<MATCHSTR>>='<<FIELD>>'] ; | stats .. | lookup def k AS f OUTPUTNEW .. ; | makeresults format=csv data=".."
EFISIEN filter awal + waktu sempit + istilah spesifik ; hindari index=* *lead NOT ; streaming->stats->lookup/sort/table ; Job Inspector
KO        extraction -> alias -> calculated -> lookup -> event type -> tag ; macro + *_filter ; workflow action (batasi field)
CIM       event type -> tag -> nama field -> nilai field ; putus satu, event hilang dari data model
ES        notable=finding | risk notable=finding group | contributing=intermediate finding | risk object=entity | threat object=observable
5 TAHAP   Review events | Assessment | Determine risk | Mitigate | Re-assess ; median + p90 ; dwell per insiden
RBA       risk rule -> index=risk -> risk factor -> finding-based detection -> finding group ; dedup sebelum sum
HUNT      config | modeling | indicator | behavior ; atomic vs composite ; baseline harus bersih
ANALITIK  rare / stats|sort count ; z / IQR / anomalydetection (annotate) ; jitter = stdev/avg, tahan: MAD/median
PEAK      P(topic research hypothesis scope plan) E(gather preprocess analyze refine escalate) A(preserve document detect backlog communicate)
SIMPAN    summary index (collect, sistats) | KV store (append=true key_field=_key) | metrics (mstats)
AR        otomatis (editor) vs ad hoc (Mission Control) ; keyakinan x reversibilitas x blast radius x kebijakan ; relay
SOAR      automation rules (Configure > Splunk SOAR) | Run playbook | response plan task | AR->SOAR ; pairing ; 1 detection : 1 rule
PLATFORM  frozen = usia ATAU ukuran ; dbinspect ; RF vs SF ; skipped (hilang) vs deferred ; cek 4 hal sebelum "tidak ada bukti"
AKSES     srchIndexesAllowed (kuat) | srchFilter (event, bocor di tstats/summary/lookup) | field filter (lookup tak terlindungi)
KONTEN    research.splunk.com/ESCU | SSE | Lantern | ES content mgmt ; buktikan data model terisi sebelum aktifkan
KASUS     identitas | aset | jaringan | eksekusi ; nyata? T0 ; siapa ; berhasil? ; setelahnya ; yang tak terlihat
```

## 8. Uji diri

Soal di bawah mencampur materi seluruh topik dengan bobot pada Day 38-46. Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Di laporan SOC-2026-0283, seorang analyst menulis "tidak ada aktivitas penyerang di `JKT-DB02` setelah login `svc_backup`", karena query proses ke host itu kosong. Query-nya benar dan berjalan tanpa error. Kenapa kalimat itu tetap salah?

<details><summary>Jawaban</summary>

Hasil kosong adalah klaim tentang cakupan, bukan temuan. Agent di `JKT-DB02` mati selama empat jam, jadi hasil kosong berarti tidak ada data, bukan tidak ada aktivitas, dan kalimat yang benar menyebut bahwa aktivitas di host itu tidak bisa dipastikan lalu menaruh alasannya di bagian keterbatasan. Secara umum, sebelum menulis "tidak ada bukti", empat hal dicek lebih dulu: peringatan hasil tidak lengkap, `scanCount` yang jauh lebih kecil dari biasanya, batas retensi nyata, dan status summary bila memakai `summariesonly=true`. Lihat bagian 1.7, 1.8, dan 1.9.

</details>

**2. Skenario keputusan.** Detection "Encoded PowerShell" di PT JAB punya FP rate 35%, sebagian besar dari skrip admin. Pimpinan ingin host diisolasi otomatis setiap kali detection itu menyala. Apa rekomendasimu?

- A. Pasang isolasi otomatis, karena PowerShell terenkode selalu berbahaya dan kecepatan lebih penting.
- B. Turunkan detection ke output intermediate finding, tambahkan allowlist sempit untuk skrip admin yang dikenal, otomatiskan enrichment saja, dan biarkan finding group RBA memicu playbook dengan prompt persetujuan sebelum isolasi.
- C. Nonaktifkan detection sampai FP rate-nya nol.

<details><summary>Jawaban</summary>

B. Keyakinan detection sedang dan blast radius isolasi tinggi, jadi menurut matriks keputusan enrichment boleh otomatis sedangkan tindakan dijalankan ad hoc atau lewat SOAR dengan persetujuan. A melipatgandakan kesalahan detection: dengan FP 35%, lebih dari sepertiga isolasi akan mengenai host yang tidak bersalah. C membuang cakupan untuk semua kasus yang benar; FP rate nol bukan syarat yang realistis, dan tuning lewat allowlist sempit serta RBA adalah cara yang memang disediakan untuk menurunkannya. Lihat bagian 1.6 dan Skenario 3 di Bagian A pada bagian 2-4.

</details>

**3. Pertanyaan jebakan.** Setelah ESCU dipasang di search head ES PT JAB, ratusan detection berstatus aktif dan dashboard cakupan ATT&CK terlihat penuh. Sumber RADIUS pelanggan juga sudah masuk index `linux` dengan volume besar. Rekanmu menyimpulkan login pelanggan sudah tercakup detection berbasis Authentication. Apa yang perlu dibuktikan dulu?

<details><summary>Jawaban</summary>

Dua hal yang berbeda. Pertama, detection aktif belum tentu bisa menyala: prasyarat datanya, yaitu data model, macro, dan lookup, harus dibuktikan, misalnya dengan `tstats count from datamodel=... by sourcetype`. Kedua, volume di index bukan jaminan event masuk data model, karena event baru masuk Authentication bila rantainya utuh: event type, tag `authentication`, nama field CIM, dan nilai `action` yang baku. Tanpa tag, event RADIUS tidak ada di data model, dan detection di atasnya tampak hijau tanpa pernah menyala. Lihat bagian 1.3, 1.7, dan glosarium di bagian 1.10.

</details>

**4. Skenario keputusan.** Hunt beaconing di segmen kantor PT JAB tidak menemukan apa pun dalam 24 jam, padahal tim jaringan yakin ada host yang menghubungi tujuan aneh setiap lima menit. SOC lead ingin menulis "tidak ada indikasi C2" di laporan mingguan. Apa yang kamu lakukan?

- A. Setujui, karena search sudah dijalankan dengan ambang jitter yang wajar.
- B. Periksa apakah sumber datanya per koneksi atau flow teragregasi, apakah filter port terlalu sempit, apakah jitter beacon besar sehingga perlu versi median dan MAD, dan apakah rentangnya cukup; tulis hasilnya sebagai "tidak ditemukan" beserta scope dan celah datanya.
- C. Turunkan ambang jitter dan jadwalkan search itu sebagai alert setiap jam.

<details><summary>Jawaban</summary>

B. Hasil "tidak ditemukan" sah hanya bila scope dan celah datanya ditulis. Flow teragregasi menghapus interval asli, filter `dest_port` 443 melewatkan beacon di port lain, koefisien variasi rusak oleh jitter atau satu interval panjang, dan rentang 24 jam bisa memuat terlalu sedikit koneksi. A memperlakukan hasil kosong sebagai bukti. C mengubah alat penyaring menjadi alert: keteraturan interval juga ciri forwarder, update checker, dan NTP, jadi long tail dan outlier menghasilkan daftar kandidat yang ditinjau manusia, bukan detection. Lihat bagian 1.5 dan Skenario 2 di Bagian A pada bagian 2-4.

</details>

**5. Pertanyaan jebakan.** Laporan SOC-2026-0283 menyebut "logon pertama `svc_backup` dari `JKT-WS-0388` pukul 02.58" berdasarkan `stats first(_time) BY src`. Seorang reviewer mempertanyakannya. Apa masalahnya?

<details><summary>Jawaban</summary>

`first()` mengembalikan nilai dari event pertama yang diproses, dan secara default Splunk memproses event terbaru lebih dulu, sehingga `first(_time)` biasanya waktu terakhir, bukan pertama. Untuk timeline, yang dipakai adalah `earliest(_time)` atau `min(_time)`. Angka 02.58 bisa saja benar bila hanya ada satu atau dua event, tetapi query-nya tidak membuktikannya, dan reviewer benar meminta query diganti sebelum angka itu dipakai sebagai T0. Lihat bagian 1.2 dan Skenario 4 di Bagian A pada bagian 2-4.

</details>

**6. Jelaskan ulang.** Jelaskan ke SOC lead PT JAB, dalam tiga kalimat, bagaimana sebuah hunt bisa menjadi pemicu finding di antrean, memakai SOC-2026-0283 sebagai contoh.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Hunt modeling membangun baseline login per akun per jam, dan karena data mentah hanya disimpan terbatas, baseline itu disimpan terjadwal di summary index dengan `sistats` dan jeda terhadap ingest lag, supaya bisa dipakai berbulan-bulan. Dari baseline itu lahir sinyal: `svc_backup` login jam 03 jauh di atas pola biasanya, dan sinyal itu menjadi finding yang membuka SOC-2026-0283, yang ternyata lateral movement dari `JKT-WS-0388`. Kasusnya lalu menghasilkan detection baru, yaitu akun layanan yang login ke host yang belum pernah dipakainya dalam 30 hari, sehingga hunt, detection, dan investigasi membentuk satu siklus."

Kesalahan yang sering muncul:
- Menganggap hunting pekerjaan terpisah yang hasilnya hanya laporan, bukan baseline dan detection.
- Lupa bahwa baseline bisa tercemar insiden atau bolong karena scheduled search yang skipped, sehingga sinyal dari baseline tetap perlu diperiksa.
- Menyebut anomali baseline sebagai bukti serangan, padahal ia hanya pemberi prioritas sampai sudut eksekusi membuktikan sesuatu.

</details>

**7. Interview question (English).** "A detection in your SIEM has not fired for a month. How do you know whether that means nothing happened?"

<details><summary>Sample answer</summary>

"I treat silence as a claim I have to prove, and I walk the chain behind the detection from the bottom up. First the data: is the source still sending, are there days with no events at all, and does the index still hold the period, because retention can cut data by size long before the configured age. Second the normalisation: if the detection reads a CIM data model, I check that the events actually land there, since a missing tag or event type leaves the index full and the data model empty without any error, and if it reads accelerated summaries, I check that acceleration is complete for that range. Third the execution: I look at the scheduler logs for skipped runs, because a skipped run is lost for good, and I compare the average run time with the schedule interval. Fourth the logic: I test the search against known-good test data, for instance a benign simulation in the lab, so I know it can fire at all. If vendor content is involved, I also confirm its prerequisites rather than assuming them. Only when all of that is clean do I say the silence means no matching activity, and even then I write down the data limitations, because 'no data' and 'no activity' are very different statements."

What makes this answer strong: it treats an empty result as a coverage question, walks a concrete chain from data to logic instead of jumping to tuning, names failure modes that produce silence without errors, and ends with reporting language that keeps the distinction visible.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | SPL Search Reference 10.2 (tstats, transaction, rex, eval, foreach, lookup, makeresults, rare, anomalydetection; Day 11-14, 25, dan 39) | https://help.splunk.com/en/splunk-enterprise/spl-search-reference/10.2/search-commands/tstats | primer | diakses 2026-10-07 | Tinggi |
| S2 | Splunk PEAK hypothesis hunting (Day 39) | https://www.splunk.com/en_us/blog/security/peak-hypothesis-driven-threat-hunting.html | primer | 2023-05-08 | Tinggi |
| S3 | ES 8.7 automation rules / adaptive response (Day 41-42) | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/automation-with-playbooks/configure-automation-rules-to-run-playbooks-based-on-findings-in-splunk-enterprise-security | primer | diakses 2026-10-07 | Tinggi |
| S4 | ES 8.7: Configure adaptive response actions for detections (Day 41) | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/detections/configure-adaptive-response-actions-for-detections-in-splunk-enterprise-security | primer | diakses 2026-10-07 | Tinggi |
| S5 | Splunk SOAR (On-premises) release notes 8.6.0 (Day 42) | https://help.splunk.com/en/splunk-soar/soar-on-premises/release-notes/8.6.0/splunk-soar-on-premises-release-notes | primer | 2026-08-04; diakses 2026-10-10 | Tinggi |
| S6 | Dragos: The Four Types of OT Threat Detection in The Dragos Platform (Pahl) (Day 38) | https://dragos.brightspotcdn.com/3e/f8/aefcee7f41b6b19a02b410ac5722/four-types-threat-detection-whitepaper-09-25.pdf | sekunder (vendor) | 2025-09; diakses 2026-10-07 | Tinggi untuk definisi; ada konten pemasaran produk |
| S7 | Splunk Enterprise 10.6 Securing Splunk: "Protect PII, PHI, and other sensitive data with field filters" (Day 44) | https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/10.6/use-field-filters-to-protect-sensitive-data | primer | diperbarui 2026-09-09, diakses 2026-10-15 | Tinggi |
| S8 | Splunk Security Content: research.splunk.com (Day 45) | https://research.splunk.com/ | primer | diakses 2026-10-07 | Tinggi. v6.7.0 saat diakses |
| S9 | What's new in Splunk Security Essentials (3.8) (Day 45) | https://help.splunk.com/en/splunk-enterprise-security-8/security-essentials/release-notes-and-resources/3.8/splunk-security-essentials-release-notes/whats-new-in-splunk-security-essentials | primer | halaman diperbarui 2025-07-22; diakses 2026-10-07 | Tinggi |
| S10 | SANS: siaran pers SANS 2026 Threat Hunting Survey (Day 39) | https://www.sans.org/press/announcements/threat-hunters-call-data-their-biggest-barrier-overtaking-staffing-first-time-survey-finds | sekunder | 2026-09-23; diakses 2026-10-10 | Sedang-tinggi |
| S11 | Managing Indexers and Clusters of Indexers: "How the indexer stores indexes", spesifikasi `indexes.conf` (Day 43) | https://help.splunk.com/en/splunk-enterprise | primer | judul halaman dirujuk 2026-10-09 | Tinggi untuk siklus bucket. URL menunjuk ke situs dokumentasi; cari halaman dari judulnya |
| S12 | Knowledge Manager Manual: "Use summary indexing for increased search efficiency" (Day 40) | https://help.splunk.com/en/splunk-enterprise | primer | judul halaman dirujuk 2026-10-09 | Tinggi untuk konsep dan nama command. URL menunjuk ke situs dokumentasi; cari halaman dari judulnya |

**Catatan sumber:** Day ini menyintesis Day 01-46 tanpa klaim teknis baru; sumber S4 sampai S12 adalah sumber Day asal yang dipakai ulang untuk klaim yang dirangkum di sini, dan hal yang masih perlu dicek di Day asalnya tetap berlaku (misalnya index hasil AR di ES 8.7 dan nama aksi AR ke SOAR). Angka survei SANS berasal dari siaran pers [S10]. Skenario di bagian 2-4 dan tabel jejak di bagian 1.9 fiktif dan memakai artefak PT JAB dari Day 40 dan Day 46.
