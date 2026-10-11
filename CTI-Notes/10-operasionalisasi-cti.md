---
day: 10
title: 'Mengoperasionalkan CTI: dari intelijen ke deteksi, hunting, dan pengayaan SIEM'
researched_on: 2026-10-10
versions_checked: 'MITRE ATT&CK v19; Sigma (spesifikasi rule SigmaHQ); Splunk lookup dan Wazuh 4.x CDB list sebagai contoh mekanisme; rujukan Day 02, 04, 07-09'
---

# Day 10: Mengoperasionalkan CTI

Cakupan: cara mengubah intelijen menjadi perubahan nyata di pertahanan lewat tiga jalur (deteksi IOC, deteksi perilaku, dan hunting), cara memperkaya alert dengan konteks CTI, cara memetakan cakupan deteksi ke ATT&CK, dan cara mengukur apakah semua itu berdampak.

## Ide inti

Intelijen yang tidak mengubah tindakan tidak bernilai (Day 01). Mengoperasionalkan CTI berarti mengubah produk intelijen menjadi perubahan yang bisa ditunjuk di pertahanan: IOC menjadi watchlist, TTP menjadi rule dan hunt, dan konteks intelijen menempel pada alert sehingga triage lebih cepat. Di tahap inilah tim CTI bertemu SOC, detection engineering, dan threat hunting. Banyak program CTI gagal justru di sini: laporan rapi terbit setiap minggu, tetapi tidak ada rule baru, tidak ada hunt, dan tidak ada perubahan prioritas yang bisa ditunjuk. Penyebabnya biasanya bukan kualitas analisis, melainkan tidak adanya jalur yang jelas dari produk CTI ke backlog tim lain, dan tidak adanya format yang bisa langsung dikerjakan tim tersebut.

Kamu sudah mengenal pola kegagalan ini dari post-mortem insiden. Laporan post-mortem yang rapi tidak ada artinya bila action item-nya tidak masuk backlog tim lain, tidak punya pemilik, dan tidak pernah ditutup. Operasionalisasi CTI adalah memastikan setiap produk intelijen punya action item seperti itu: indikator masuk sebagai lookup di SIEM, perilaku menjadi use case request yang berujung rule teruji, dan sisanya menjadi hunt. Ukurannya sama dengan ukuran post-mortem yang berhasil: berapa action item yang benar-benar selesai.

```
Produk CTI (profil ISET-FICTA, CTI-2026-041)
  -> nilai (domain, hash)               -> watchlist IOC (lookup / CDB list) + pencarian retroaktif
  -> procedure + telemetri jelas        -> rule perilaku (Sigma) -> uji simulasi + data normal
  -> procedure ambigu / data belum dicek -> hunt berhipotesis -> temuan menjadi rule atau insiden
  -> konteks profil                     -> pengayaan alert (sumber, keyakinan, TTP berikutnya)
Semua jalur -> peta cakupan ATT&CK + metrik -> umpan balik ke TIP dan PIR
```

Situasi yang dipakai sepanjang Day ini: profil ISET-FICTA dari Day 09 sudah diterbitkan di PT Logistik Contoh (PT LC) sebagai produk internal CTI-2026-041, dengan keputusan dua rule baru dan dua hunt dalam 30 hari. Lead SOC membalas di thread distribusinya:

> "Profilnya sudah saya baca. Sekarang konkretnya: (1) mana yang masuk SIEM sebagai watchlist, mana yang jadi rule, mana yang di-hunt? (2) Domain-domain itu dipasang bagaimana di Splunk dan Wazuh supaya tidak jadi sampah tiga bulan lagi? (3) Detection engineer minta satu rule yang bisa diuji. (4) Untuk yang belum bisa jadi rule, hunt-nya seperti apa? (5) Analyst L1 mengeluh alert IOC cuma bilang 'match' tanpa konteks. (6) CISO pasti tanya: dari TTP aktor itu berapa yang sudah kita deteksi, dan apa buktinya CTI berdampak?"

Pertanyaan 1 adalah pemilahan jalur (bagian 1.1 dan 1.2). Pertanyaan 2 adalah watchlist (bagian 1.3, 2.1, dan 2.2). Pertanyaan 3 adalah rule perilaku (bagian 1.4 dan 2.3). Pertanyaan 4 adalah hipotesis hunt (bagian 1.5 dan 2.4). Pertanyaan 5 adalah pengayaan alert (bagian 1.6 dan 2.5). Pertanyaan 6 adalah peta cakupan dan metrik (bagian 1.7, 1.8, dan 2.6).

**Kapan relevan:** setiap kali intelijen baru masuk dan relevan dengan PIR, saat menyusun backlog deteksi dan hunt, dan saat menilai cakupan deteksi terhadap ancaman yang relevan.
**Kapan bukan jawaban:** saat masalahnya adalah kesepakatan antar tim. CTI tidak bisa memaksa tim lain bertindak; operasionalisasi butuh kesepakatan proses, misalnya SLA untuk permintaan deteksi dari CTI.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Tabel ini memuat istilah yang muncul di Day ini. Kolom padanan memakai analogi SOC yang sama di semua Day CTI. Istilah dari Day sebelumnya (IOC, keyakinan dan expiry, TIP, warninglist, sighting, Pyramid of Pain, PIR, procedure) tidak diulang.

| Istilah | Arti singkat | Padanan di SOC |
|---|---|---|
| Operasionalisasi CTI | Mengubah intelijen menjadi perubahan yang bisa ditunjuk di pertahanan | Action item post-mortem yang benar-benar masuk backlog dan ditutup |
| Watchlist IOC | Tabel indikator berkonteks yang dicocokkan dengan field di log | Blocklist atau lookup di SIEM |
| Pencarian retroaktif | Mencari IOC baru di log masa lalu | Re-run search lama setelah ada indikator baru |
| Sigma | Format rule deteksi generik berbasis YAML yang bisa dikonversi ke query berbagai SIEM | Correlation search yang ditulis sekali dalam format netral |
| CDB list | Berkas `key:value` di Wazuh yang dirujuk rule untuk pencocokan | Lookup di Wazuh |
| Hipotesis hunt | Pernyataan yang bisa dibuktikan benar atau salah dengan data yang tersedia | Hunt berbasis hipotesis |
| Kriteria selesai | Syarat kapan hipotesis terbukti, tidak terbukti, atau tidak bisa diuji | Definition of done sebuah tiket |
| Beaconing | Koneksi berkala dengan interval relatif tetap dari implant ke C2 | Pola koneksi periodik di log proxy |
| Jitter | Variasi acak yang ditambahkan ke interval beaconing | Noise yang membuat ambang statis meleset |
| Pengayaan (enrichment) | Menempelkan konteks CTI ke alert yang sudah ada | Enrichment otomatis di playbook SOAR |
| Peta cakupan ATT&CK | Daftar technique aktor relevan beserta status deteksinya | Coverage matrix use case SOC |
| Atomic Red Team | Katalog simulasi per technique untuk menguji rule | Test case untuk membuktikan rule menyala |

### 1.1 Apa itu operasionalisasi

Pertanyaan Lead SOC ("sekarang konkretnya") adalah ujian operasionalisasi: profil ISET-FICTA baru bernilai bila ada yang berubah di SIEM, EDR, atau backlog.

Mengoperasionalkan CTI berarti mengubah intelijen menjadi perubahan yang bisa ditunjuk di pertahanan: rule baru, watchlist, hunt yang dijalankan, pengayaan alert, perubahan prioritas patch, atau kontrol baru. Ini bagian dissemination siklus intelijen (Day 02) yang paling konkret.

Ukurannya bukan jumlah laporan, melainkan perubahan yang terjadi. Bila kamu tidak bisa menunjuk satu rule, hunt, atau keputusan yang lahir dari produk CTI bulan ini, operasionalisasinya belum berjalan.

### 1.2 Tiga jalur

Pertanyaan pertama Lead SOC meminta isi profil dipilah. Tabel berikut membandingkan tiga jalur yang tersedia. Baca kolom "Masukan" untuk tahu isi profil mana yang cocok untuk tiap jalur, dan kolom "Kelemahan" untuk tahu kenapa satu jalur saja tidak cukup.

| Jalur | Masukan | Keluaran | Kekuatan | Kelemahan |
|---|---|---|---|---|
| Deteksi IOC | IOC tervalidasi dengan keyakinan dan expiry (Day 07) | Watchlist dan correlation di SIEM, blokir di kontrol perimeter | Cepat dibuat, false positive rendah bila IOC bagus | Mudah dielak, cepat basi |
| Deteksi perilaku | Procedure dan technique ATT&CK dari profil (Day 09) | Rule berbasis perilaku, misalnya dalam format Sigma | Tahan lama; penyerang harus mengubah cara kerja | Butuh telemetri yang tepat dan tuning |
| Hunting | Hipotesis dari CTI | Hunt terstruktur; temuan menjadi rule atau insiden | Menemukan yang lolos deteksi, menguji asumsi | Mahal waktu; hasil tidak pasti |

Ketiganya saling melengkapi. Deteksi IOC adalah lantai: menangkap yang sudah dikenal. Deteksi perilaku menaikkan biaya bagi penyerang sesuai Pyramid of Pain (Day 04). Hunting mencari yang belum punya rule, lalu mengubah temuannya menjadi rule.

Aturan praktis untuk memilah: bila yang kamu pegang adalah nilai (domain, hash), masuk jalur IOC. Bila yang kamu pegang adalah procedure yang telemetrinya tersedia dan pola normalnya jelas, masuk jalur deteksi perilaku. Bila procedure-nya terlalu mirip aktivitas sah untuk dijadikan rule langsung, atau telemetrinya belum pernah kamu periksa, masuk jalur hunt dulu. Untuk ISET-FICTA, domain masuk watchlist (bagian 2.1 dan 2.2), scheduled task dari ProgramData menjadi rule (bagian 2.3), dan beaconing serta unggahan ke cloud storage di-hunt dulu (bagian 2.4).

### 1.3 IOC ke watchlist SIEM

Kekhawatiran Lead SOC bahwa domain "jadi sampah tiga bulan lagi" adalah masalah expiry dan pemeliharaan. Mekanisme yang umum adalah tabel pencocokan yang dibandingkan dengan field di log:

- **Splunk:** lookup (berkas CSV atau KV store) yang dipanggil dengan command `lookup` di search, atau dipasang sebagai automatic lookup pada sourcetype. Hasilnya dipakai di correlation search yang menghasilkan alert.
- **Wazuh 4.x:** CDB list, yaitu berkas teks berisi baris `key:value` di direktori lists manager, dideklarasikan di bagian `<ruleset>` konfigurasi manager, lalu dirujuk oleh rule dengan elemen `<list field="..." lookup="match_key">` [S4]. Rule akan menyala bila nilai field di event yang sudah di-decode ada di list.

Prasyarat yang sama berlaku di kedua platform:

- Hanya IOC yang lolos validasi, punya keyakinan, dan punya expiry (Day 07) yang masuk.
- Tabel menyimpan konteks (kampanye, keyakinan, expiry, id sumber), bukan hanya nilai, agar alert yang dihasilkan sudah membawa konteks.
- Ada proses otomatis yang memperbarui tabel dari TIP (Day 08) dan membuang entri yang kedaluwarsa.
- Nilai disimpan tanpa defang dan dalam bentuk ternormalisasi (huruf kecil untuk domain, tanpa titik di akhir).

Pertimbangkan juga pencarian retroaktif. IOC baru yang masuk hari ini bisa dicari di log 30-90 hari ke belakang. Hit retroaktif sering lebih penting daripada hit baru, karena menandakan kompromi yang mungkin sudah berjalan.

### 1.4 TTP ke deteksi perilaku dengan Sigma

Detection engineer PT LC meminta satu rule yang bisa diuji, dan rule itu sebaiknya tidak terkunci ke satu SIEM karena contoh di Day ini memakai Splunk dan Wazuh. Sigma adalah format rule deteksi generik berbasis YAML yang bisa dikonversi ke bahasa query berbagai SIEM [S2].

Tabel berikut memuat bagian rule Sigma yang perlu kamu kenali. Perhatikan baris `tags` dan `description`: di sanalah rule berbasis CTI menyimpan kaitan ke ATT&CK dan ke produk asalnya.

| Field | Isi |
|---|---|
| `title`, `id`, `status` | Nama, UUID unik, dan status kematangan (misalnya `experimental`, `test`, `stable`) |
| `description`, `references`, `author`, `date` | Konteks; `references` bisa menunjuk produk CTI internal |
| `tags` | Pemetaan ATT&CK, misalnya `attack.persistence`, `attack.t1053.005` |
| `logsource` | Sumber log: `product` (windows), `category` (process_creation) atau `service` (security) |
| `detection` | Satu atau lebih selection berisi field dan nilai, ditambah `condition` yang menggabungkannya |
| `falsepositives` | Aktivitas sah yang diketahui bisa memicu rule |
| `level` | `informational`, `low`, `medium`, `high`, `critical` |

Modifier pada nama field mengubah cara pencocokan, misalnya `Image|endswith`, `CommandLine|contains`, atau `CommandLine|contains|all` (semua nilai harus ada).

Langkah dari procedure ke rule:

1. Ambil procedure dari profil (Day 09), bukan hanya nama technique.
2. Tentukan telemetri yang memperlihatkannya dan pastikan telemetri itu benar-benar dikumpulkan.
3. Tulis selection yang menangkap ciri procedure, lalu filter untuk aktivitas sah yang diketahui.
4. Uji dengan kasus positif (simulasi procedure di lab, misalnya dari katalog Atomic Red Team [S5]) dan kasus negatif (data normal satu sampai dua minggu).
5. Konversi ke query SIEM, pasang dengan level yang sesuai, pantau false positive, lalu tune.

Rule berbasis CTI sebaiknya punya rujukan balik ke produk CTI asalnya (di `references` atau `description`). Ini memudahkan pengukuran dampak dan peninjauan ulang ketika penilaian aktor berubah.

### 1.5 CTI ke hipotesis hunt

Dua TTP ISET-FICTA (HTTPS berinterval tetap dan unggahan ke cloud storage) terlalu mirip aktivitas sah untuk langsung dijadikan rule, sehingga Lead SOC perlu hunt. Hunt yang baik dimulai dari hipotesis yang bisa diuji: pernyataan yang bisa dibuktikan benar atau salah dengan data yang tersedia. Struktur yang berguna:

- **Dasar intelijen:** produk atau profil apa, dan keyakinannya.
- **Hipotesis:** "bila aktor X sudah berada di lingkungan kita dan memakai procedure Y, maka di data Z akan terlihat pola W."
- **Data:** sumber log, rentang waktu, dan cakupan host.
- **Langkah analisis:** query, agregasi, dan cara memisahkan yang normal dari yang mencurigakan.
- **Kriteria selesai:** kapan hipotesis dinyatakan terbukti, tidak terbukti, atau tidak bisa diuji karena data kurang.
- **Keluaran:** insiden, rule baru, perbaikan telemetri, atau catatan celah.

Hasil "tidak terbukti" bukan kegagalan. Itu bukti bahwa, dengan data yang ada, procedure itu tidak terlihat. Hasil "tidak bisa diuji karena data kurang" juga berharga, karena menjadi permintaan perbaikan telemetri yang bisa diajukan dengan dasar intelijen.

Contoh analisis yang sering diturunkan dari CTI adalah beaconing: implant yang menghubungi C2 dengan interval relatif tetap. Cara umum menilainya adalah mengelompokkan koneksi per pasangan host sumber dan tujuan, menghitung selisih waktu antar koneksi, lalu melihat seberapa seragam selisih itu. Pasangan dengan banyak koneksi, selisih yang seragam, dan ukuran respons yang mirip patut diperiksa. Jebakannya: agen update, telemetri aplikasi, dan monitoring juga berperilaku periodik, jadi daftar tujuan sah yang dikenal harus disaring lebih dulu. Penyerang juga menambahkan jitter, sehingga ambang keseragaman tidak boleh terlalu ketat.

### 1.6 Pengayaan alert

Keluhan analyst L1 ("cuma bilang match") menunjukkan watchlist sudah berjalan tetapi konteksnya tidak sampai ke meja triage. CTI memperkaya alert yang sudah ada sehingga triage lebih cepat. Saat alert menyebut IP, domain, atau hash, pengayaan otomatis menambahkan reputasi, kaitan kampanye atau aktor, keyakinan, tanggal terakhir terlihat, dan rekomendasi tindakan dari TIP.

Dua cara pengayaan:

- **Saat pencarian:** alert memanggil lookup yang sama dengan watchlist untuk menambah field konteks. Cepat dan sederhana, tetapi konteksnya hanya sekaya tabelnya.
- **Lewat SOAR atau integrasi TIP:** alert memicu query ke API TIP dan hasilnya ditempelkan ke tiket. Konteks lebih kaya, tetapi menambah ketergantungan dan latensi.

Pengayaan juga bisa menyesatkan. Label "dikenal berbahaya" dari feed berkualitas rendah bisa membuat analis menaikkan prioritas tanpa alasan. Sertakan selalu sumber dan keyakinan di field pengayaan, bukan hanya label.

### 1.7 Peta cakupan ATT&CK

Pertanyaan CISO yang diantisipasi Lead SOC ("berapa yang sudah kita deteksi") dijawab dengan peta cakupan: dari teknik yang dipakai aktor relevan, mana yang bisa kita deteksi [S1]. Langkahnya:

1. Kumpulkan technique dari profil aktor yang relevan (Day 09). Gabungan beberapa aktor menghasilkan daftar prioritas: technique yang dipakai banyak aktor relevan di atas.
2. Untuk tiap technique, catat status deteksi: tidak ada, sebagian, atau ada dan teruji. Status "ada" hanya boleh diberikan bila rule pernah diuji dengan simulasi.
3. Visualisasikan sebagai layer ATT&CK Navigator (berkas JSON berisi daftar technique dengan skor atau warna) atau sebagai tabel.
4. Tetapkan backlog dari celah dengan prioritas tertinggi.

Jebakan peta cakupan adalah warna hijau yang menipu. Satu rule untuk T1059.001 tidak berarti seluruh penyalahgunaan PowerShell tercakup. Catat procedure apa yang dicakup, bukan hanya technique-nya.

### 1.8 Mengukur dan menutup siklus

Bagian kedua pertanyaan CISO ("apa buktinya CTI berdampak") butuh angka, dan angka yang tepat bukan jumlah laporan. Tabel berikut membagi metrik ke empat jenis. Perhatikan kolom "Kegunaan": metrik keluaran membuktikan jalur berjalan, tetapi hanya metrik dampak yang meyakinkan pimpinan.

| Jenis | Contoh metrik | Kegunaan |
|---|---|---|
| Keluaran | Jumlah rule, watchlist, dan hunt yang lahir dari produk CTI per bulan | Membuktikan jalur berjalan |
| Kualitas | Rasio true positive dan false positive per rule dan per sumber IOC | Menilai sumber dan tuning |
| Dampak | Insiden atau temuan hunt yang berawal dari deteksi berbasis CTI; waktu dari laporan terbit sampai rule terpasang | Membuktikan nilai ke pimpinan |
| Cakupan | Persentase technique prioritas dengan deteksi teruji | Menunjukkan arah perbaikan |

Umpan balik yang menutup siklus: false positive dari SOC kembali ke TIP sebagai sighting atau penurunan keyakinan; temuan hunt menjadi rule; celah telemetri menjadi PIR atau permintaan collection baru (Day 02). Tanpa ini, operasionalisasi hanya berjalan sekali.

## 2. Contoh artefak intelijen

Semua contoh di bagian ini fiktif dan berupa keluaran ilustrasi. IOC di-defang di teks, ditulis apa adanya di dalam tabel pencocokan karena dibaca mesin. Nama index, sourcetype, dan field mengikuti lab fiktif dan perlu disesuaikan dengan lingkunganmu. Keenam artefak di bawah adalah jawaban tim PT LC untuk enam pertanyaan Lead SOC di bagian Ide inti.

### 2.1 Watchlist domain di Splunk

Ini jawaban untuk pertanyaan kedua di sisi Splunk: domain dari profil ISET-FICTA disimpan bersama konteks dan expiry-nya.

Isi lookup `cti_domains.csv`:

```
domain,campaign,confidence,expiry,source_id
bad-logistics.example,LOGI-FICTA,60,2027-01-08,indicator--8e2e2d2b
invoice-check.example,LOGI-FICTA,40,2026-11-10,indicator--1c0a77e1
```

Search pencocokan:

```
index=dns_lab sourcetype=dns_fiktif
| eval query=lower(rtrim(query, "."))
| lookup cti_domains domain AS query OUTPUT campaign confidence expiry source_id
| where isnotnull(campaign) AND strptime(expiry, "%Y-%m-%d") > now()
| stats count min(_time) AS first_seen max(_time) AS last_seen values(src) AS src_hosts BY query campaign confidence source_id
```

Penjelasan tiap bagian: `eval` menormalkan nilai agar cocok dengan isi lookup; `lookup` menempelkan field konteks bila domain ada di tabel; `where` membuang yang tidak cocok dan yang sudah kedaluwarsa; `stats` merangkum per domain, sehingga satu domain yang di-query seratus kali menghasilkan satu baris.

Keluaran ilustrasi:

```
query                  campaign    confidence  source_id            count  src_hosts
bad-logistics.example  LOGI-FICTA  60          indicator--8e2e2d2b  14     WS-021, WS-044
```

**Cara membaca hasil:** dua host melakukan 14 query. Langkah berikutnya bukan langsung isolasi, tetapi memeriksa proses yang membuat query itu dan apa yang terjadi sesudahnya. Keyakinan 60 berarti alert ini layak prioritas tinggi untuk diperiksa, bukan bukti kompromi.

**Kapan gagal:** bila log DNS menyimpan query dengan huruf besar atau titik akhir dan normalisasi dilupakan, tidak ada yang cocok. Bila field `expiry` kosong, `strptime` menghasilkan null dan baris dibuang diam-diam, jadi pastikan setiap entri punya expiry.

### 2.2 Watchlist domain di Wazuh 4.x

Ini jawaban untuk pertanyaan kedua di sisi Wazuh, dengan catatan penting soal expiry yang tidak dikenal CDB list.

Isi CDB list `cti-domains` (satu entri per baris, format `key:value`):

```
bad-logistics.example:LOGI-FICTA-60
invoice-check.example:LOGI-FICTA-40
```

Rule yang merujuknya:

```xml
<group name="cti,">
  <rule id="100510" level="10">
    <if_group>dns</if_group>
    <list field="dns.query" lookup="match_key">etc/lists/cti-domains</list>
    <description>CTI: query DNS ke domain watchlist $(dns.query)</description>
    <group>cti_watchlist,</group>
  </rule>
</group>
```

Penjelasan: `<if_group>` membatasi rule ke event yang sudah dikelompokkan sebagai DNS; `<list>` mencocokkan nilai field hasil decoder dengan key di list; `level` menentukan prioritas alert. Nama field `dns.query` dan grup `dns` di sini fiktif; pakai nama yang dihasilkan decoder di lingkunganmu. List juga harus dideklarasikan di bagian `<ruleset>` konfigurasi manager, dan manager perlu di-restart setelah list berubah.

**Kapan gagal:** CDB list tidak mengenal expiry, jadi entri kedaluwarsa harus dibuang oleh proses yang menulis ulang list dari TIP. Tanpa proses itu, list hanya bertambah.

### 2.3 Procedure ke rule Sigma

Ini jawaban untuk pertanyaan ketiga. Procedure dari profil ISET-FICTA (Day 09): membuat scheduled task bernama mirip layanan pembaruan yang menjalankan skrip dari ProgramData.

```yaml
title: Scheduled Task Dibuat dengan Aksi dari ProgramData (CTI ISET-FICTA)
id: 7d1b8c0e-2f4a-4c55-9d5e-0b8a3f61c2aa
status: experimental
description: Pembuatan scheduled task lewat schtasks yang menjalankan berkas dari ProgramData. Diturunkan dari profil ISET-FICTA (produk CTI internal CTI-2026-041).
references:
  - CTI-2026-041 (internal, TLP:AMBER)
author: tim CTI lab
date: 2026-10-10
tags:
  - attack.persistence
  - attack.t1053.005
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\schtasks.exe'
    CommandLine|contains|all:
      - '/create'
      - '\ProgramData\'
  filter_known:
    ParentImage|endswith: '\agen-inventaris-fiktif.exe'
  condition: selection and not filter_known
falsepositives:
  - Installer atau agen manajemen yang menaruh berkas di ProgramData
level: medium
```

**Cara membaca hasil:** rule ini menangkap procedure, bukan nama task tertentu, sehingga tetap berguna walaupun aktor mengganti nama task. Filter mengecualikan agen sah yang diketahui berperilaku serupa di lingkungan lab.

**Cara menguji:** jalankan simulasi T1053.005 dari katalog Atomic Red Team di VM lab terisolasi, varian yang membuat task lewat `schtasks /create`. Yang harus terlihat di log adalah event pembuatan proses `schtasks.exe` dengan command line memuat `/create` dan path aksi. Lalu jalankan rule terhadap data normal satu sampai dua minggu dan catat jumlah false positive.

**Kapan gagal:** task yang dibuat lewat API atau PowerShell `Register-ScheduledTask` tidak melewati `schtasks.exe`, jadi rule ini tidak melihatnya. Pasangkan dengan rule kedua berbasis event pembuatan task (Security 4698) bila log itu diaktifkan.

### 2.4 Hipotesis hunt dari profil

Ini jawaban untuk pertanyaan keempat: dua TTP yang belum bisa dijadikan rule digabung dalam satu hunt dengan kriteria selesai yang jelas.

```
Hunt H-2026-07 (fiktif)
Dasar      : profil ISET-FICTA, keyakinan sedang ; TTP T1071.001 dan T1567.002
Hipotesis  : Bila ISET-FICTA sudah berada di jaringan kita, maka ada host yang melakukan
             koneksi HTTPS dengan interval seragam ke domain yang didaftarkan < 30 hari,
             dan/atau mengunggah > 500 MB ke layanan cloud storage di luar jam kerja.
Data       : log proxy 30 hari, log DNS 30 hari, inventaris host
Langkah    : 1) buang tujuan sah yang dikenal (update OS, AV, telemetri SaaS)
             2) per pasangan host-domain: jumlah koneksi, rata-rata dan simpangan selisih waktu
             3) tandai pasangan dengan koneksi > 50/hari dan simpangan < 10% rata-rata
             4) gabungkan dengan umur domain (pengayaan WHOIS)
             5) terpisah: total byte keluar per host ke kategori cloud storage, di luar jam kerja
Selesai    : terbukti bila ada pasangan yang lolos 3) dan 4) tanpa penjelasan sah ;
             tidak terbukti bila semua kandidat punya penjelasan ; tidak bisa diuji bila
             log proxy tidak memuat ukuran respons
Keluaran   : insiden, rule beaconing berbasis ambang hasil hunt, atau permintaan telemetri
```

**Cara membaca hasil:** keluaran ilustrasi menunjukkan dua pasangan lolos langkah 3; keduanya ternyata agen backup yang dikenal. Hipotesis tidak terbukti; ambang dan daftar pengecualian disimpan sebagai bahan rule.

### 2.5 Alert sebelum dan sesudah pengayaan

Ini jawaban untuk keluhan analyst L1 di pertanyaan kelima: alert yang sama, sebelum dan sesudah konteks CTI ditempelkan.

```
Sebelum : DNS query ke bad-logistics.example dari WS-021
Sesudah : DNS query ke bad-logistics[.]example dari WS-021
          + kampanye   : LOGI-FICTA (ISET-FICTA), keyakinan 60
          + sumber     : laporan vendor A (B2), indicator--8e2e2d2b, expiry 2027-01-08
          + konteks    : domain didaftarkan 2026-09-26 ; ISET-FICTA memakai T1053.005 dan T1567.002
          + rekomendasi: periksa proses pembuat query ; cari scheduled task baru di WS-021 ;
                         cek upload besar dari WS-021 ; isolasi bila ada temuan pendukung
```

**Cara membaca hasil:** rekomendasi yang menyebut TTP berikutnya dari profil adalah nilai tambah terbesar pengayaan: analis tahu apa yang harus dicari selanjutnya.

### 2.6 Peta cakupan ringkas

Ini jawaban untuk pertanyaan keenam: technique dari aktor relevan, siapa yang memakainya, status deteksi PT LC, dan tindakan berikutnya.

```
Technique   Dipakai oleh (aktor relevan)   Status deteksi          Tindakan
T1566.001   ISET-FICTA, aktor B, aktor C   sebagian (gateway)      tambah rule .js dalam zip
T1059.007   ISET-FICTA                     tidak ada               rule baru (backlog P1)
T1053.005   ISET-FICTA, aktor B            ada, teruji 2026-10-10  pantau FP
T1071.001   ISET-FICTA, aktor C            tidak ada               hunt H-2026-07 dulu
T1567.002   ISET-FICTA                     tidak ada               hunt H-2026-07 dulu
T1486       ISET-FICTA, aktor B            ada, belum teruji       uji simulasi
```

**Cara membaca hasil:** baris T1486 berstatus "ada, belum teruji", jadi belum boleh dihitung sebagai cakupan teruji di metrik bagian 1.8 sampai simulasinya dijalankan.

## 3. Lab praktik

**Prasyarat:** SIEM lab (Splunk atau Wazuh) di VM lab terisolasi dengan data DNS dan process creation, profil fiktif dari Day 09, dan IOC fiktif dari Day 07. Simulasi teknik hanya di VM lab dengan snapshot.

1. **Pilah jalur.** Dari profil ISET-FICTA atau profil-mu sendiri, pilah setiap isi ke jalur IOC, deteksi perilaku, atau hunt, beserta alasan satu kalimat.
2. **Watchlist.** Buat lookup atau CDB list dengan minimal lima IOC fiktif lengkap dengan konteks. Tambahkan satu entri yang sudah kedaluwarsa dan buktikan search atau proses pembaruanmu membuangnya.
3. **Hit retroaktif.** Jalankan pencarian IOC terhadap 30 hari data lab dan catat hasilnya.
4. **Sigma.** Tulis satu rule Sigma dari procedure profil, konversi ke query SIEM lab, uji dengan simulasi Atomic Red Team yang relevan, lalu jalankan terhadap data normal dan catat false positive.
5. **Hunt.** Tulis satu hipotesis hunt lengkap dengan kriteria selesai, jalankan di data lab, dan tulis hasilnya: terbukti, tidak terbukti, atau tidak bisa diuji.
6. **Pengayaan.** Ambil satu alert lab dan tulis versi sebelum dan sesudah pengayaan, termasuk rekomendasi berbasis TTP profil.
7. **Cakupan.** Buat peta cakupan untuk technique profil, dengan status yang hanya "teruji" bila kamu benar-benar mengujinya.
8. **Metrik.** Tetapkan empat metrik (keluaran, kualitas, dampak, cakupan) dengan cara pengumpulannya.

**Hasil yang sebaiknya tersimpan:**

- Tabel pemilahan jalur dengan alasan.
- Lookup atau CDB list beserta bukti entri kedaluwarsa terbuang.
- Hasil pencarian retroaktif.
- Rule Sigma, query hasil konversi, hasil uji positif, dan jumlah false positive di data normal.
- Catatan hunt dengan kesimpulan dan keluarannya.
- Contoh alert sebelum dan sesudah pengayaan.
- Peta cakupan dan backlog celah.
- Definisi empat metrik.

**Variasi tantangan:** operasionalkan profil yang sama hanya lewat jalur IOC, lalu simulasikan aktor yang mengganti seluruh domain dan hash. Tulis apa yang masih terdeteksi dan apa yang hilang, lalu bandingkan dengan pendekatan tiga jalur.

## 4. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| CTI tidak mengubah apa pun | Tidak ada jalur ke backlog tim lain | Sepakati format permintaan deteksi dan SLA |
| Watchlist tidak pernah cocok | Nilai tidak dinormalisasi atau masih ter-defang | Samakan huruf, buang titik akhir, refang |
| Watchlist berisik | IOC basi atau generik | Filter keyakinan dan expiry; warninglist (Day 08) |
| Entri kedaluwarsa tetap memicu alert | Mekanisme tidak mengenal expiry | Proses pembaruan dari TIP yang menulis ulang list |
| Rule perilaku tidak pernah menyala saat simulasi | Telemetri tidak dikumpulkan atau field berbeda | Cek log mentah dari simulasi sebelum menyalahkan rule |
| Hunt tidak selesai-selesai | Hipotesis tanpa kriteria selesai | Tulis kriteria terbukti, tidak terbukti, tidak bisa diuji |
| Peta cakupan hijau tapi insiden lolos | Status "ada" tanpa uji | Hanya "teruji" setelah simulasi; catat procedure yang dicakup |

## 5. Kesalahan umum dan jebakan

- **Berhenti di laporan.** Produk tanpa jalur ke tindakan tidak bernilai.
- **Hanya operasionalisasi IOC.** Mudah dielak; tambah deteksi perilaku dan hunt.
- **Rule dari nama technique, bukan procedure.** Hasilnya terlalu luas dan berisik.
- **Tidak menguji rule dengan simulasi.** Rule yang belum pernah menyala belum terbukti bekerja.
- **Lupa pencarian retroaktif.** Kompromi lama terlewat.
- **Pengayaan tanpa sumber dan keyakinan.** Label "berbahaya" tanpa konteks menyesatkan triage.
- **Tidak mengukur.** Tanpa metrik, nilai CTI tidak terlihat dan dukungan program melemah.

## 6. Catatan terkini

Bagian ini menampung perubahan versi dan perkembangan format yang memengaruhi pemeliharaan rule dan peta cakupan.

- Pemetaan deteksi ke ATT&CK untuk mengukur cakupan terhadap aktor relevan sudah menjadi praktik umum. ATT&CK v19 mengubah sebagian struktur tactic, sehingga peta cakupan dan tag rule lama perlu ditinjau saat migrasi versi.
- Sigma tetap format rule generik yang paling umum untuk memindahkan logika antar SIEM; STIX 2.1 juga mengizinkan Indicator dengan `pattern_type` sigma (Day 07) sehingga rule bisa dibagikan lewat TIP.
- Mekanisme watchlist di SIEM (lookup, CDB list, threat intelligence framework bawaan produk) berbeda antar produk dan versi; prinsip validasi, konteks, dan expiry tetap sama.

## 7. Cheat sheet

```
OPERASIONAL  intelijen -> perubahan yang bisa DITUNJUK (rule, watchlist, hunt, prioritas) ; ukur perubahan, bukan laporan
3 JALUR      nilai -> watchlist IOC | procedure + telemetri jelas -> rule perilaku | procedure ambigu/telemetri belum dicek -> hunt
WATCHLIST    hanya IOC tervalidasi + keyakinan + expiry ; simpan konteks ; normalisasi ; pembaruan otomatis dari TIP ; RETROAKTIF
SPLUNK       lookup cti_domains domain AS query OUTPUT ... | where isnotnull(campaign) AND expiry > now()
WAZUH        CDB list key:value ; deklarasi di <ruleset> ; rule <list field="..." lookup="match_key"> ; tanpa expiry bawaan
SIGMA        title id status | tags attack.tXXXX | logsource product/category | detection selection + condition | falsepositives | level
UJI RULE     simulasi positif (Atomic Red Team, lab) + data normal 1-2 minggu -> hitung FP -> tune
HUNT         dasar intelijen | hipotesis jika..maka | data | langkah | kriteria selesai | keluaran
BEACONING    per host-tujuan: jumlah koneksi + keseragaman selisih waktu ; buang tujuan sah ; ingat jitter
ENRICH       konteks + sumber + keyakinan + TTP berikutnya untuk dicari
CAKUPAN      technique aktor relevan -> status (tidak ada / sebagian / teruji) -> backlog ; catat procedure, bukan hanya ID
METRIK       keluaran | kualitas (TP/FP per rule dan sumber) | dampak (temuan, waktu laporan->rule) | cakupan
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Peta cakupan PT LC menandai T1059.001 hijau karena ada satu rule PowerShell yang sudah diuji. Apakah itu berarti penyalahgunaan PowerShell oleh aktor relevan sudah tercakup?

<details><summary>Jawaban</summary>

Tidak. Satu rule untuk sebuah technique tidak berarti seluruh penyalahgunaan technique itu tercakup; itulah jebakan warna hijau yang menipu. Peta cakupan harus mencatat procedure apa yang dicakup, bukan hanya ID technique-nya, dan status "ada" hanya boleh diberikan bila rule pernah diuji dengan simulasi. Lihat bagian 1.7.

</details>

**2. Skenario keputusan.** Profil ISET-FICTA menyebut procedure "HTTPS ke domain baru dengan interval tetap". Detection engineer belum pernah memeriksa apakah log proxy PT LC memuat ukuran respons. Jalur mana yang tepat?

- A. Watchlist IOC, karena procedure ini menyangkut domain.
- B. Rule perilaku langsung, karena beaconing adalah perilaku yang jelas.
- C. Hunt dulu, karena perilaku periodik mirip aktivitas sah (agen update, monitoring) dan telemetrinya belum diperiksa.

<details><summary>Jawaban</summary>

C. Aturan praktisnya: procedure yang terlalu mirip aktivitas sah, atau yang telemetrinya belum pernah diperiksa, masuk jalur hunt dulu. Hunt H-2026-07 juga menentukan ambang dan daftar pengecualian yang nanti menjadi bahan rule. A keliru karena watchlist hanya untuk nilai seperti domain dan hash, sedangkan yang dipegang di sini adalah perilaku; domain baru juga terus berganti. B keliru karena rule beaconing tanpa daftar tujuan sah dan ambang yang diuji akan berisik, dan penyerang menambahkan jitter. Lihat bagian 1.2, 1.5, dan 2.4.

</details>

**3. Pertanyaan jebakan.** Hunt H-2026-07 berakhir "tidak terbukti": dua kandidat ternyata agen backup. Apakah waktu tim terbuang?

<details><summary>Jawaban</summary>

Tidak. Hasil "tidak terbukti" adalah bukti bahwa, dengan data yang ada, procedure itu tidak terlihat. Hunt ini juga menghasilkan ambang dan daftar pengecualian yang disimpan sebagai bahan rule. Hasil "tidak bisa diuji" pun berharga karena menjadi permintaan perbaikan telemetri berdasar intelijen. Yang membuat hunt bisa disimpulkan adalah kriteria selesai yang ditulis sebelum mulai. Lihat bagian 1.5 dan 2.4.

</details>

**4. Skenario keputusan.** Di Wazuh lab PT LC, domain yang sudah kedaluwarsa bulan lalu masih memicu alert watchlist. Apa perbaikan yang tepat?

- A. Turunkan `level` rule supaya alert tidak terlalu mengganggu.
- B. Tambahkan kolom expiry di CDB list, seperti kolom `expiry` di lookup Splunk.
- C. Buat proses yang menulis ulang CDB list dari TIP dan membuang entri kedaluwarsa, lalu restart manager setelah list berubah.

<details><summary>Jawaban</summary>

C. CDB list tidak mengenal expiry, jadi entri kedaluwarsa harus dibuang oleh proses yang menulis ulang list dari TIP; tanpa proses itu list hanya bertambah. Manager juga perlu di-restart setelah list berubah. A keliru karena hanya menyembunyikan masalah dan menurunkan prioritas alert yang mungkin valid. B keliru karena CDB list hanya berformat `key:value`, sehingga tidak ada kolom expiry yang dievaluasi rule seperti `where ... strptime(expiry, ...)` di Splunk. Lihat bagian 1.3, 2.1, dan 2.2.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Lead SOC dalam tiga kalimat kenapa profil ISET-FICTA tidak cukup dioperasionalkan lewat watchlist IOC saja.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Watchlist domain dan hash cepat dibuat dan jarang false positive, tetapi mudah dielak karena aktor tinggal mengganti domain dan hash, dan nilainya cepat basi. Perilaku seperti membuat scheduled task dari ProgramData lebih tahan lama, jadi kita ubah menjadi rule Sigma yang diuji dengan simulasi. Untuk perilaku yang terlalu mirip aktivitas sah, seperti koneksi berkala dan unggahan ke cloud storage, kita hunt dulu, lalu temuan dan ambangnya dijadikan rule."

Kesalahan yang sering muncul:
- Menganggap jalur IOC tidak berguna sama sekali, padahal watchlist adalah lantai yang menangkap yang sudah dikenal.
- Langsung menulis rule dari nama technique, sehingga rule terlalu luas dan berisik.
- Lupa bahwa hunting juga menghasilkan rule, sehingga ketiga jalur terlihat terpisah.

</details>

**6. Pertanyaan jebakan.** Rule Sigma "schtasks /create dengan path ProgramData" sudah lolos uji simulasi Atomic Red Team. Apakah semua scheduled task jahat ISET-FICTA pasti terlihat?

<details><summary>Jawaban</summary>

Tidak. Task yang dibuat lewat API atau PowerShell `Register-ScheduledTask` tidak melewati `schtasks.exe`, jadi rule ini tidak melihatnya. Rule perlu dipasangkan dengan rule kedua berbasis event pembuatan task (Security 4698) bila log itu diaktifkan. Lolos uji simulasi hanya membuktikan rule menyala untuk varian yang diuji. Lihat bagian 2.3.

</details>

**7. Interview question (English).** "You've just finished a threat actor profile. How do you make sure it actually changes something in your defences?"

<details><summary>Sample answer</summary>

"I split the profile into three tracks. Indicators that are validated and carry confidence and an expiry date go into a SIEM watchlist, with context stored alongside the value and a retroactive search over the last 30 to 90 days. Procedures with clear telemetry become behaviour-based rules, which I write in Sigma, reference back to the intel product, and test with a lab simulation plus a week or two of normal data to measure false positives. Behaviours that look too much like legitimate activity, like periodic beaconing, start as hypothesis-driven hunts with clear completion criteria, and the findings or thresholds become rules. I also push the profile's context into alert enrichment, and I track coverage on an ATT&CK map where 'covered' only means 'tested'. Finally I measure output, quality, impact, and coverage, so I can show leadership which rules and findings came from intelligence."

What makes this answer strong: it matches each type of content to the right track, insists on testing and expiry, treats hunting as a source of new detections, and ends with metrics that prove impact rather than counting reports.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | MITRE ATT&CK | https://attack.mitre.org/ | primer | diakses 2026-10-09 | Tinggi. Technique, procedure, dasar peta cakupan |
| S2 | SigmaHQ: Sigma detection format | https://sigmahq.io/ | primer | diakses 2026-10-09 | Tinggi. Struktur rule, modifier, logsource |
| S3 | David Bianco: The Pyramid of Pain | https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html | primer | diakses 2026-10-09 | Tinggi. Nilai TTP dibanding IOC |
| S4 | Wazuh documentation: CDB lists | https://documentation.wazuh.com/current/user-manual/ruleset/cdb-list.html | primer | diakses 2026-10-10 | Tinggi. Format list, deklarasi, dan pemakaian di rule |
| S5 | Red Canary: Atomic Red Team | https://github.com/redcanaryco/atomic-red-team | primer | diakses 2026-10-10 | Tinggi. Katalog simulasi per technique untuk menguji rule |
| S6 | CTI-note Day 02, 04, 07-09 | (lokal) | rujukan internal | 2026-10-09 | Siklus, Pyramid, IOC, TIP, profil |

**Catatan sumber:** nama field, grup decoder, dan sourcetype di bagian 2 fiktif dan harus disesuaikan dengan lingkunganmu. Ambang beaconing di hunt H-2026-07 adalah titik awal ilustrasi, bukan nilai baku; tentukan dari distribusi data lab-mu. Perilaku pemuatan ulang CDB list setelah diubah bisa berbeda antar versi Wazuh 4.x, jadi cek di dokumentasi versi-mu.
