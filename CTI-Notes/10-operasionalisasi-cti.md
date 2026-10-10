---
day: 10
title: 'Mengoperasionalkan CTI: dari intelijen ke deteksi, hunting, dan pengayaan SIEM'
researched_on: 2026-10-10
versions_checked: 'MITRE ATT&CK v19; Sigma (spesifikasi rule SigmaHQ); Splunk lookup dan Wazuh 4.x CDB list sebagai contoh mekanisme; rujukan Day 02, 04, 07-09'
---

# Day 10: Mengoperasionalkan CTI

Cakupan: cara mengubah intelijen menjadi perubahan nyata di pertahanan lewat tiga jalur (deteksi IOC, deteksi perilaku, dan hunting), cara memperkaya alert dengan konteks CTI, dan cara mengukur apakah semua itu berdampak.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- menjelaskan apa artinya mengoperasionalkan CTI dan kenapa banyak program CTI gagal di tahap ini.
- memilah isi satu laporan atau profil ke jalur yang tepat: watchlist IOC, deteksi perilaku, atau hunt.
- merancang watchlist IOC di SIEM yang menghormati keyakinan dan expiry, dengan contoh Splunk lookup dan Wazuh CDB list.
- menulis rule Sigma sederhana dari satu procedure aktor dan menjelaskan cara mengujinya.
- menurunkan hipotesis hunt yang bisa diuji dari profil aktor.
- memakai CTI untuk pengayaan alert dan memetakan cakupan deteksi ke ATT&CK.
- menetapkan metrik keluaran dan dampak yang menutup siklus intelijen.

## 2. Konteks singkat

Intelijen yang tidak mengubah tindakan tidak bernilai (Day 01). Mengoperasionalkan CTI adalah jembatan dari analisis ke pertahanan: IOC menjadi watchlist, TTP menjadi rule dan hunt, dan konteks intelijen menempel pada alert sehingga triage lebih cepat. Di tahap inilah tim CTI bertemu SOC, detection engineering, dan threat hunting.

Banyak program CTI gagal justru di sini. Mereka menerbitkan laporan rapi setiap minggu, tetapi tidak ada rule baru, tidak ada hunt, dan tidak ada perubahan prioritas yang bisa ditunjuk. Penyebabnya biasanya bukan kualitas analisis, melainkan tidak adanya jalur yang jelas dari produk CTI ke backlog tim lain, dan tidak adanya format yang bisa langsung dikerjakan oleh tim tersebut.

**Kapan dipakai:** setiap kali intelijen baru masuk dan relevan dengan PIR; saat menyusun backlog deteksi dan hunt; saat menilai cakupan deteksi terhadap ancaman yang relevan.

**Kapan terbatas:** CTI tidak bisa memaksa tim lain bertindak. Operasionalisasi butuh kesepakatan proses, misalnya SLA untuk permintaan deteksi dari CTI.

## 3. Konsep inti

### 3.1 Apa itu operasionalisasi

Mengoperasionalkan CTI berarti mengubah intelijen menjadi perubahan yang bisa ditunjuk di pertahanan: rule baru, watchlist, hunt yang dijalankan, pengayaan alert, perubahan prioritas patch, atau kontrol baru. Ini bagian dissemination siklus intelijen (Day 02) yang paling konkret.

Ukurannya bukan jumlah laporan, melainkan perubahan yang terjadi. Bila kamu tidak bisa menunjuk satu rule, hunt, atau keputusan yang lahir dari produk CTI bulan ini, operasionalisasinya belum berjalan.

### 3.2 Tiga jalur

| Jalur | Masukan | Keluaran | Kekuatan | Kelemahan |
|---|---|---|---|---|
| Deteksi IOC | IOC tervalidasi dengan keyakinan dan expiry (Day 07) | Watchlist dan correlation di SIEM, blokir di kontrol perimeter | Cepat dibuat, false positive rendah bila IOC bagus | Mudah dielak, cepat basi |
| Deteksi perilaku | Procedure dan technique ATT&CK dari profil (Day 09) | Rule berbasis perilaku, misalnya dalam format Sigma | Tahan lama; penyerang harus mengubah cara kerja | Butuh telemetri yang tepat dan tuning |
| Hunting | Hipotesis dari CTI | Hunt terstruktur; temuan menjadi rule atau insiden | Menemukan yang lolos deteksi, menguji asumsi | Mahal waktu; hasil tidak pasti |

Ketiganya saling melengkapi. Deteksi IOC adalah lantai: menangkap yang sudah dikenal. Deteksi perilaku menaikkan biaya bagi penyerang sesuai Pyramid of Pain (Day 04). Hunting mencari yang belum punya rule, lalu mengubah temuannya menjadi rule.

Aturan praktis untuk memilah: bila yang kamu pegang adalah nilai (domain, hash), masuk jalur IOC. Bila yang kamu pegang adalah procedure yang telemetrinya tersedia dan pola normalnya jelas, masuk jalur deteksi perilaku. Bila procedure-nya terlalu mirip aktivitas sah untuk dijadikan rule langsung, atau telemetrinya belum pernah kamu periksa, masuk jalur hunt dulu.

### 3.3 IOC ke watchlist SIEM

Mekanisme yang umum adalah tabel pencocokan yang dibandingkan dengan field di log:

- **Splunk:** lookup (berkas CSV atau KV store) yang dipanggil dengan command `lookup` di search, atau dipasang sebagai automatic lookup pada sourcetype. Hasilnya dipakai di correlation search yang menghasilkan alert.
- **Wazuh 4.x:** CDB list, yaitu berkas teks berisi baris `key:value` di direktori lists manager, dideklarasikan di bagian `<ruleset>` konfigurasi manager, lalu dirujuk oleh rule dengan elemen `<list field="..." lookup="match_key">`. Rule akan menyala bila nilai field di event yang sudah di-decode ada di list.

Prasyarat yang sama berlaku di kedua platform:

- Hanya IOC yang lolos validasi, punya keyakinan, dan punya expiry (Day 07) yang masuk.
- Tabel menyimpan konteks (kampanye, keyakinan, expiry, id sumber), bukan hanya nilai, agar alert yang dihasilkan sudah membawa konteks.
- Ada proses otomatis yang memperbarui tabel dari TIP (Day 08) dan membuang entri yang kedaluwarsa.
- Nilai disimpan tanpa defang dan dalam bentuk ternormalisasi (huruf kecil untuk domain, tanpa titik di akhir).

Pertimbangkan juga pencarian retroaktif. IOC baru yang masuk hari ini bisa dicari di log 30-90 hari ke belakang. Hit retroaktif sering lebih penting daripada hit baru, karena menandakan kompromi yang mungkin sudah berjalan.

### 3.4 TTP ke deteksi perilaku dengan Sigma

Sigma adalah format rule deteksi generik berbasis YAML yang bisa dikonversi ke bahasa query berbagai SIEM [S2]. Bagian rule Sigma yang perlu kamu kenali:

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
4. Uji dengan kasus positif (simulasi procedure di lab) dan kasus negatif (data normal satu sampai dua minggu).
5. Konversi ke query SIEM, pasang dengan level yang sesuai, pantau false positive, lalu tune.

Rule berbasis CTI sebaiknya punya rujukan balik ke produk CTI asalnya (di `references` atau `description`). Ini memudahkan pengukuran dampak dan peninjauan ulang ketika penilaian aktor berubah.

### 3.5 CTI ke hipotesis hunt

Hunt yang baik dimulai dari hipotesis yang bisa diuji: pernyataan yang bisa dibuktikan benar atau salah dengan data yang tersedia. Struktur yang berguna:

- **Dasar intelijen:** produk atau profil apa, dan keyakinannya.
- **Hipotesis:** "bila aktor X sudah berada di lingkungan kita dan memakai procedure Y, maka di data Z akan terlihat pola W."
- **Data:** sumber log, rentang waktu, dan cakupan host.
- **Langkah analisis:** query, agregasi, dan cara memisahkan yang normal dari yang mencurigakan.
- **Kriteria selesai:** kapan hipotesis dinyatakan terbukti, tidak terbukti, atau tidak bisa diuji karena data kurang.
- **Keluaran:** insiden, rule baru, perbaikan telemetri, atau catatan celah.

Hasil "tidak terbukti" bukan kegagalan. Itu bukti bahwa, dengan data yang ada, procedure itu tidak terlihat. Hasil "tidak bisa diuji karena data kurang" juga berharga, karena menjadi permintaan perbaikan telemetri yang bisa diajukan dengan dasar intelijen.

Contoh analisis yang sering diturunkan dari CTI adalah beaconing: implant yang menghubungi C2 dengan interval relatif tetap. Cara umum menilainya adalah mengelompokkan koneksi per pasangan host sumber dan tujuan, menghitung selisih waktu antar koneksi, lalu melihat seberapa seragam selisih itu. Pasangan dengan banyak koneksi, selisih yang seragam, dan ukuran respons yang mirip patut diperiksa. Jebakannya: agen update, telemetri aplikasi, dan monitoring juga berperilaku periodik, jadi daftar tujuan sah yang dikenal harus disaring lebih dulu. Penyerang juga menambahkan jitter, sehingga ambang keseragaman tidak boleh terlalu ketat.

### 3.6 Pengayaan alert

CTI memperkaya alert yang sudah ada sehingga triage lebih cepat. Saat alert menyebut IP, domain, atau hash, pengayaan otomatis menambahkan reputasi, kaitan kampanye atau aktor, keyakinan, tanggal terakhir terlihat, dan rekomendasi tindakan dari TIP.

Dua cara pengayaan:

- **Saat pencarian:** alert memanggil lookup yang sama dengan watchlist untuk menambah field konteks. Cepat dan sederhana, tetapi konteksnya hanya sekaya tabelnya.
- **Lewat SOAR atau integrasi TIP:** alert memicu query ke API TIP dan hasilnya ditempelkan ke tiket. Konteks lebih kaya, tetapi menambah ketergantungan dan latensi.

Perhatikan bahwa pengayaan juga bisa menyesatkan. Label "dikenal berbahaya" dari feed berkualitas rendah bisa membuat analis menaikkan prioritas tanpa alasan. Sertakan selalu sumber dan keyakinan di field pengayaan, bukan hanya label.

### 3.7 Peta cakupan ATT&CK

Peta cakupan menjawab "dari teknik yang dipakai aktor relevan, mana yang bisa kita deteksi". Langkahnya:

1. Kumpulkan technique dari profil aktor yang relevan (Day 09). Gabungan beberapa aktor menghasilkan daftar prioritas: technique yang dipakai banyak aktor relevan di atas.
2. Untuk tiap technique, catat status deteksi: tidak ada, sebagian, atau ada dan teruji. Status "ada" hanya boleh diberikan bila rule pernah diuji dengan simulasi.
3. Visualisasikan sebagai layer ATT&CK Navigator (berkas JSON berisi daftar technique dengan skor atau warna) atau sebagai tabel.
4. Tetapkan backlog dari celah dengan prioritas tertinggi.

Jebakan peta cakupan adalah warna hijau yang menipu. Satu rule untuk T1059.001 tidak berarti seluruh penyalahgunaan PowerShell tercakup. Catat procedure apa yang dicakup, bukan hanya technique-nya.

### 3.8 Mengukur dan menutup siklus

| Jenis | Contoh metrik | Kegunaan |
|---|---|---|
| Keluaran | Jumlah rule, watchlist, dan hunt yang lahir dari produk CTI per bulan | Membuktikan jalur berjalan |
| Kualitas | Rasio true positive dan false positive per rule dan per sumber IOC | Menilai sumber dan tuning |
| Dampak | Insiden atau temuan hunt yang berawal dari deteksi berbasis CTI; waktu dari laporan terbit sampai rule terpasang | Membuktikan nilai ke pimpinan |
| Cakupan | Persentase technique prioritas dengan deteksi teruji | Menunjukkan arah perbaikan |

Umpan balik yang menutup siklus: false positive dari SOC kembali ke TIP sebagai sighting atau penurunan keyakinan; temuan hunt menjadi rule; celah telemetri menjadi PIR atau permintaan collection baru (Day 02). Tanpa ini, operasionalisasi hanya berjalan sekali.

## 4. Contoh artefak intelijen

Semua contoh di bagian ini fiktif dan berupa keluaran ilustrasi. IOC di-defang di teks, ditulis apa adanya di dalam tabel pencocokan karena dibaca mesin. Nama index, sourcetype, dan field mengikuti lab fiktif dan perlu disesuaikan dengan lingkunganmu.

### 4.1 Watchlist domain di Splunk

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

Cara membaca: dua host melakukan 14 query. Langkah berikutnya bukan langsung isolasi, tetapi memeriksa proses yang membuat query itu dan apa yang terjadi sesudahnya. Keyakinan 60 berarti alert ini layak prioritas tinggi untuk diperiksa, bukan bukti kompromi.

Kapan gagal: bila log DNS menyimpan query dengan huruf besar atau titik akhir dan normalisasi dilupakan, tidak ada yang cocok. Bila field `expiry` kosong, `strptime` menghasilkan null dan baris dibuang diam-diam, jadi pastikan setiap entri punya expiry.

### 4.2 Watchlist domain di Wazuh 4.x

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

Kapan gagal: CDB list tidak mengenal expiry, jadi entri kedaluwarsa harus dibuang oleh proses yang menulis ulang list dari TIP. Tanpa proses itu, list hanya bertambah.

### 4.3 Procedure ke rule Sigma

Procedure dari profil ISET-FICTA (Day 09): membuat scheduled task bernama mirip layanan pembaruan yang menjalankan skrip dari ProgramData.

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

Cara membaca: rule ini menangkap procedure, bukan nama task tertentu, sehingga tetap berguna walaupun aktor mengganti nama task. Filter mengecualikan agen sah yang diketahui berperilaku serupa di lingkungan lab.

Cara menguji: jalankan simulasi T1053.005 dari katalog Atomic Red Team di VM lab terisolasi, varian yang membuat task lewat `schtasks /create`. Yang harus terlihat di log adalah event pembuatan proses `schtasks.exe` dengan command line memuat `/create` dan path aksi. Lalu jalankan rule terhadap data normal satu sampai dua minggu dan catat jumlah false positive.

Kapan gagal: task yang dibuat lewat API atau PowerShell `Register-ScheduledTask` tidak melewati `schtasks.exe`, jadi rule ini tidak melihatnya. Pasangkan dengan rule kedua berbasis event pembuatan task (Security 4698) bila log itu diaktifkan.

### 4.4 Hipotesis hunt dari profil

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

Keluaran ilustrasi: dua pasangan lolos langkah 3; keduanya ternyata agen backup yang dikenal. Hipotesis tidak terbukti; ambang dan daftar pengecualian disimpan sebagai bahan rule.

### 4.5 Alert sebelum dan sesudah pengayaan

```
Sebelum : DNS query ke bad-logistics.example dari WS-021
Sesudah : DNS query ke bad-logistics[.]example dari WS-021
          + kampanye   : LOGI-FICTA (ISET-FICTA), keyakinan 60
          + sumber     : laporan vendor A (B2), indicator--8e2e2d2b, expiry 2027-01-08
          + konteks    : domain didaftarkan 2026-09-26 ; ISET-FICTA memakai T1053.005 dan T1567.002
          + rekomendasi: periksa proses pembuat query ; cari scheduled task baru di WS-021 ;
                         cek upload besar dari WS-021 ; isolasi bila ada temuan pendukung
```

Rekomendasi yang menyebut TTP berikutnya dari profil adalah nilai tambah terbesar pengayaan: analis tahu apa yang harus dicari selanjutnya.

### 4.6 Peta cakupan ringkas

```
Technique   Dipakai oleh (aktor relevan)   Status deteksi          Tindakan
T1566.001   ISET-FICTA, aktor B, aktor C   sebagian (gateway)      tambah rule .js dalam zip
T1059.007   ISET-FICTA                     tidak ada               rule baru (backlog P1)
T1053.005   ISET-FICTA, aktor B            ada, teruji 2026-10-10  pantau FP
T1071.001   ISET-FICTA, aktor C            tidak ada               hunt H-2026-07 dulu
T1567.002   ISET-FICTA                     tidak ada               hunt H-2026-07 dulu
T1486       ISET-FICTA, aktor B            ada, belum teruji       uji simulasi
```

## 5. Lab praktik (di VM lab terisolasi)

**Prasyarat:** SIEM lab (Splunk atau Wazuh) dengan data DNS dan process creation, profil fiktif dari Day 09, dan IOC fiktif dari Day 07. Simulasi teknik hanya di VM lab dengan snapshot.

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

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| CTI tidak mengubah apa pun | Tidak ada jalur ke backlog tim lain | Sepakati format permintaan deteksi dan SLA |
| Watchlist tidak pernah cocok | Nilai tidak dinormalisasi atau masih ter-defang | Samakan huruf, buang titik akhir, refang |
| Watchlist berisik | IOC basi atau generik | Filter keyakinan dan expiry; warninglist (Day 08) |
| Entri kedaluwarsa tetap memicu alert | Mekanisme tidak mengenal expiry | Proses pembaruan dari TIP yang menulis ulang list |
| Rule perilaku tidak pernah menyala saat simulasi | Telemetri tidak dikumpulkan atau field berbeda | Cek log mentah dari simulasi sebelum menyalahkan rule |
| Hunt tidak selesai-selesai | Hipotesis tanpa kriteria selesai | Tulis kriteria terbukti, tidak terbukti, tidak bisa diuji |
| Peta cakupan hijau tapi insiden lolos | Status "ada" tanpa uji | Hanya "teruji" setelah simulasi; catat procedure yang dicakup |

## 7. Kesalahan umum dan jebakan

- **Berhenti di laporan.** Produk tanpa jalur ke tindakan tidak bernilai.
- **Hanya operasionalisasi IOC.** Mudah dielak; tambah deteksi perilaku dan hunt.
- **Rule dari nama technique, bukan procedure.** Hasilnya terlalu luas dan berisik.
- **Tidak menguji rule dengan simulasi.** Rule yang belum pernah menyala belum terbukti bekerja.
- **Lupa pencarian retroaktif.** Kompromi lama terlewat.
- **Pengayaan tanpa sumber dan keyakinan.** Label "berbahaya" tanpa konteks menyesatkan triage.
- **Tidak mengukur.** Tanpa metrik, nilai CTI tidak terlihat dan dukungan program melemah.

## 8. Catatan terkini

- Pemetaan deteksi ke ATT&CK untuk mengukur cakupan terhadap aktor relevan sudah menjadi praktik umum. ATT&CK v19 mengubah sebagian struktur tactic, sehingga peta cakupan dan tag rule lama perlu ditinjau saat migrasi versi.
- Sigma tetap format rule generik yang paling umum untuk memindahkan logika antar SIEM; STIX 2.1 juga mengizinkan Indicator dengan `pattern_type` sigma (Day 07) sehingga rule bisa dibagikan lewat TIP.
- Mekanisme watchlist di SIEM (lookup, CDB list, threat intelligence framework bawaan produk) berbeda antar produk dan versi; prinsip validasi, konteks, dan expiry tetap sama.

## 9. Cheat sheet

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

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | MITRE ATT&CK | https://attack.mitre.org/ | primer | diakses 2026-10-09 | Tinggi. Technique, procedure, dasar peta cakupan |
| S2 | SigmaHQ: Sigma detection format | https://sigmahq.io/ | primer | diakses 2026-10-09 | Tinggi. Struktur rule, modifier, logsource |
| S3 | David Bianco: The Pyramid of Pain | https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html | primer | diakses 2026-10-09 | Tinggi. Nilai TTP dibanding IOC |
| S4 | Wazuh documentation: CDB lists | https://documentation.wazuh.com/current/user-manual/ruleset/cdb-list.html | primer | diakses 2026-10-10 | Tinggi. Format list, deklarasi, dan pemakaian di rule |
| S5 | Red Canary: Atomic Red Team | https://github.com/redcanaryco/atomic-red-team | primer | diakses 2026-10-10 | Tinggi. Katalog simulasi per technique untuk menguji rule |
| S6 | CTI-note Day 02, 04, 07-09 | (lokal) | rujukan internal | 2026-10-09 | Siklus, Pyramid, IOC, TIP, profil |

**Catatan sumber:** nama field, grup decoder, dan sourcetype di bagian 4 fiktif dan harus disesuaikan dengan lingkunganmu. Ambang beaconing di hunt H-2026-07 adalah titik awal ilustrasi, bukan nilai baku; tentukan dari distribusi data lab-mu. Perilaku pemuatan ulang CDB list setelah diubah bisa berbeda antar versi Wazuh 4.x, jadi cek di dokumentasi versi-mu.
