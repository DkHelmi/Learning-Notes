---
day: 10
title: 'Acceleration dan Asset & Identity framework: dari summary data model sampai konteks src_priority dan user_category'
researched_on: 2026-10-07
versions_checked: Splunk Enterprise Security 8.7 (Add asset and identity data; Configure asset and identity correlation; Asset and identity fields after processing); Splunk CIM 6.4; Splunk Enterprise 10.6 (Knowledge Manager Manual 10.4 untuk acceleration)
---

# Day 10: Acceleration dan Asset & Identity framework

Cakupan: akselerasi data model (summary, ukuran, pemantauan) dan Asset and Identity framework di ES untuk memperkaya finding dengan konteks aset dan identitas.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- menjelaskan siklus hidup data model acceleration (build, summary range, enforcement oleh ES) dan cara memantaunya.
- menjelaskan Asset & Identity (A&I) framework ES: sumber data, lookup hasil merge, field aset/identitas, dan bagaimana korelasinya memperkaya event.
- membaca field enrichment seperti `src_priority`, `dest_category`, dan `user_bunit`, lalu memakainya untuk prioritas triage.
- mendiagnosis kenapa aset atau identitas "unknown" dan dampaknya pada detection dan risk.

## 2. Konteks singkat

Day 01 dan Day 09 sudah membahas akselerasi dari sisi `tstats`. Hari ini kita melihatnya dari sisi operasi ES, lalu masuk ke konteks yang membuat alert bisa diprioritaskan: siapa user ini (eksekutif? admin? kontraktor yang sudah keluar?) dan apa host ini (server pembayaran? laptop lab?).

Alert yang sama, "login gagal 50 kali", punya arti berbeda bila targetnya domain controller berprioritas *critical* atau VM uji berprioritas *low*. Tanpa A&I, analyst menebak. Dengan A&I, ES mengisi konteks itu secara otomatis dan memakainya dalam risk scoring (Day 22).

## 3. Konsep inti

### 3.1 Acceleration dari sisi operasi ES

Rangkuman dari Day 01 dan Day 09, ditambah sisi operasional:
- Akselerasi membangun summary tsidx di indexer untuk field data model. Search terjadwal sekitar setiap 5 menit, summary range menentukan cakupan waktu, dan max summarization search time default sekitar 1 jam [S1].
- Akselerasi data model CIM nonaktif secara default. Saat ES terpasang, akselerasi dipaksakan oleh ES lewat mekanisme enforcement [S2].
- Summary hanya mencerminkan definisi model saat dibangun. Mengubah constraint atau field berarti summary harus dibangun ulang (lihat `allow_old_summaries`, Day 01).
- Biaya: disk di indexer, CPU dari search akselerasi, dan beban scheduler. Lantern menyarankan perencanaan kapasitas dan audit rutin. Angka perkiraan penyimpanan di Lantern ("sekitar 3,4x volume input harian" per tahun), cek konteks dan satuannya sebelum dikutip.

**Prinsip:** akselerasikan data model yang dipakai detection/dashboard, batasi index lewat allowlist, dan pilih summary range sesuai kebutuhan detection (bukan "All time").

### 3.2 Apa itu Asset & Identity framework

ES memakai sistem aset dan identitas untuk mengorelasikan informasi aset/identitas dengan event, sehingga event diperkaya konteks saat search [S3].

Sumber data di ES 8.7 [S3]:
1. Exposure Analytics entity discovery, sumber yang diutamakan dan otomatis bila tersedia, cek lisensi/ketersediaan Exposure Analytics di deployment-mu.
2. Lookup CSV manual lewat Asset and Identity Manager.
3. LDAP/Active Directory.
4. Penyedia cloud.

Alur penambahan data [S3]:

```
kumpulkan data -> format sebagai lookup -> lookup definition -> daftarkan di Asset and Identity Manager -> verifikasi
```

Setelah itu, identity manager (modular input) memproses semua konfigurasi dan menggabungkan (merge) data berdasarkan field kunci dan kebijakan yang kamu tentukan. Hasilnya ditulis ke lookup gabungan, antara lain [S3]:
- `asset_lookup_by_str`: pencocokan string (IP tunggal, nama, MAC);
- `asset_lookup_by_cidr`: pencocokan rentang jaringan;
- `identity_lookup_expanded`.

Akses pengelolaan membutuhkan capability `edit_modinput_identity_manager` [S3].

### 3.3 Field aset dan identitas

Aset (setelah pemrosesan) [S4]:

| Field | Arti / pemrosesan |
|---|---|
| `ip` | Divalidasi dan dipecah ke subnet CIDR bila perlu; multivalue |
| `mac`, `nt_host`, `dns` | Pengenal lain; menjadi kunci pencocokan |
| `asset_id`, `asset` | Diturunkan dari ip/mac/nt_host/dns |
| `owner`, `priority`, `bunit`, `category` | Konteks bisnis. `category` diperkaya "pci" bila mengandung "cardholder" |
| `pci_domain` | wireless/trust/untrust/cardholder/dmz |
| `is_expected`, `should_timesync`, `should_update`, `requires_av` | Dinormalkan ke boolean |
| `lat`, `long`, `city`, `country` | Lokasi |
| `asset_tag` | Dibangkitkan dari category, pci_domain, flag boolean, dan bunit |
| `cim_entity_zone` | Hanya bila entity zones aktif |

Identitas [S4]:

| Field | Arti / pemrosesan |
|---|---|
| `identity` | Dibangkitkan dari baris input dan konvensi di Identity Lookup Configuration; multivalue (mis. `alice`, `LAB\alice`, `alice@lab.example`) |
| `identity_id` | Dari identity, first, last, email |
| `first`, `last`, `email`, `prefix`, `suffix`, `nick`, `phone`, `managedBy` | Atribut orang |
| `priority`, `bunit`, `category` | Konteks bisnis/risiko |
| `watchlist` | Boolean, untuk user yang perlu diawasi |
| `startDate`, `endDate` | Masa kerja. Aktivitas setelah `endDate` adalah sinyal kuat |
| `work_city`, `work_country`, `work_lat`, `work_long` | Lokasi kerja |
| `identity_tag` | Dari bunit, category, watchlist |

Nilai `priority` yang umum dipakai ES adalah `unknown`, `low`, `medium`, `high`, `critical`. Halaman pemrosesan field tidak menyebut daftar nilai yang diizinkan [S4], cek di dokumentasi format lookup aset/identitas.

### 3.4 Korelasi: bagaimana event diperkaya

Saat korelasi aktif, ES membandingkan event dengan daftar aset/identitas memakai automatic lookup saat search [S5]:
- **Aset:** field event `src`, `dest`, atau `dvc` dicocokkan dengan IP, MAC, nama DNS, atau nama NetBIOS di daftar aset.
- **Identitas:** field `user` atau `src_user` dicocokkan dengan daftar identitas.
- Field hasil diberi prefiks sesuai field asalnya. Contoh: `src` menghasilkan `src_is_expected`, `src_should_timesync`, dan seterusnya. Pola yang sama memberi `src_priority`, `dest_category`, `user_bunit`, cek nama persis di event lab-mu.
- **Penting:** korelasi tidak lagi otomatis dilakukan terhadap field `host` atau `orig_host` [S5]. Jadi event yang hanya punya `host` tidak akan diperkaya kecuali dinormalkan ke `dest`/`src`/`dvc` lewat CIM (Day 09).

Pengaturan di Configure > All configurations > Assets and identities > Correlation setup [S5]:
- aktif untuk semua sourcetype (default bila tidak memakai search head deployer);
- nonaktif;
- selektif per sourcetype.

Dokumentasi memperingatkan bahwa menonaktifkan korelasi bisa membuat detection dan dashboard tidak bekerja sebagaimana mestinya [S5].

### 3.5 Kenapa A&I penting untuk detection dan risk

- **Prioritas finding/notable:** urgensi biasanya dihitung dari severity detection dan prioritas aset/identitas yang terlibat, cek matriks urgensi di ES 8 (Day 20).
- **Risk-Based Alerting:** risk score diberikan ke entity (dulu *risk object*). Konteks seperti `priority`, `category`, dan `watchlist` dipakai untuk memodulasi skor (Day 22).
- **Konteks investigasi:** pemilik aset, unit bisnis, dan kontak manajer mempercepat eskalasi.
- **Sinyal sendiri:** login oleh identitas dengan `endDate` di masa lalu, atau trafik dari aset yang `is_expected=false`.

### 3.6 Enterprise vs ES

| Kemampuan | Splunk Enterprise | ES |
|---|---|---|
| Akselerasi data model | Ya | Ya + enforcement |
| Lookup aset/identitas buatan sendiri (CSV/KV) dan automatic lookup | Ya (dibangun manual) | Framework A&I lengkap: merge, CIDR, konvensi identitas, enrichment otomatis |
| Exposure Analytics entity discovery | Tidak | ES 8.x (bila tersedia) [S3] |
| Field `src_priority`, `user_category` otomatis | Tidak | Ya [S5] |

## 4. Contoh SPL dan langkah di ES

> Keluaran berlabel ilustrasi. Query yang memakai lookup ES (`asset_lookup_by_str`, `identity_lookup_expanded`) hanya berjalan di ES. Untuk lab tanpa ES, lihat bagian 4.5.

### 4.1 Status akselerasi data model

```
| rest /services/admin/summarization by_tstats=t splunk_server=local count=0
| eval datamodel=replace('summary.id', "DM_" . 'eai:acl.app' . "_", "")
| table datamodel summary.complete summary.size summary.earliest_time summary.latest_time summary.is_inprogress
```

- Endpoint `admin/summarization` mengembalikan status summary akselerasi. Pola ini umum dipakai komunitas, cek nama endpoint dan field di versi-mu.
- `summary.complete` mendekati 1 berarti selesai dibangun. `summary.size` menunjukkan disk.
- Alternatif UI: Settings > Data models (kolom status) atau Data Model Audit di ES [S2].

### 4.2 Melihat isi lookup aset dan identitas (ES)

```
| inputlookup asset_lookup_by_str
| stats count BY priority category bunit
| sort - count
```

```
| inputlookup identity_lookup_expanded
| eval ended=if(isnotnull(endDate) AND strptime(endDate, "%Y-%m-%d") < now(), "yes", "no")
| stats count BY priority watchlist ended
```

- Query pertama: distribusi aset menurut prioritas/kategori. Banyak `unknown` berarti data aset kurang lengkap.
- Query kedua: berapa identitas yang sudah berakhir masa kerjanya. Format tanggal `endDate` adalah asumsi, perlu dicek.

### 4.3 Event yang diperkaya: triage berbasis prioritas

```
| tstats summariesonly=true count from datamodel=Authentication
    where Authentication.action="failure"
    by Authentication.src Authentication.dest Authentication.user Authentication.dest_priority Authentication.user_category
| rename Authentication.* AS *
| eval dest_priority=coalesce(dest_priority, "unknown")
| eval rank=case(dest_priority=="critical",4, dest_priority=="high",3, dest_priority=="medium",2, dest_priority=="low",1, true(),0)
| sort - rank - count
```

- Bila A&I aktif, field seperti `dest_priority` dan `user_category` diisi oleh korelasi aset/identitas. Referensi CIM mencantumkan field ini di data model Authentication dengan catatan "disediakan otomatis" oleh korelasi A&I (Day 11). Cek field ini benar-benar terisi di summary data model lab-mu, karena nilainya bergantung pada korelasi saat summary dibangun.
- `case()` mengubah prioritas menjadi angka urut untuk sorting.
- **Cara membaca hasil:** baris teratas adalah kegagalan login terhadap aset kritis. Mulai triage dari sana.

### 4.4 Mengukur cakupan A&I: berapa entitas yang tidak dikenal?

```
| tstats count from datamodel=Authentication by Authentication.dest Authentication.dest_priority
| rename Authentication.* AS *
| eval known=if(isnull(dest_priority) OR dest_priority="unknown", "unknown", "known")
| stats dc(dest) AS hosts sum(count) AS events BY known
```

- Persentase host "unknown" adalah metrik kualitas data yang bagus untuk dilaporkan.
- **Kapan gagal:** host diidentifikasi dengan nama berbeda (FQDN vs NetBIOS) dari daftar aset, sehingga tidak cocok. Lengkapi field `dns` dan `nt_host` di sumber aset.

### 4.5 Lab tanpa ES: meniru enrichment dengan lookup biasa

```
index=wineventlog sourcetype="XmlWinEventLog:Security" EventCode=4625
| stats count BY dest user
| lookup lab_assets.csv nt_host AS dest OUTPUTNEW priority AS dest_priority owner AS dest_owner
| lookup lab_identities.csv identity AS user OUTPUTNEW priority AS user_priority endDate AS user_endDate
| fillnull value="unknown" dest_priority user_priority
```

- Sama dengan pola Day 04, tetapi dengan nama field gaya ES (`dest_priority`, `user_priority`) agar kebiasaanmu cocok dengan ES.
- Untuk otomatis, jadikan automatic lookup di Settings > Lookups. Ini analog sederhana dari korelasi ES.
- Cek nama index dan field di lab-mu.

### 4.6 Langkah di ES (generik)

1. Assets and identities > Correlation setup (jalur: Configure > All configurations > Assets and identities) untuk memastikan korelasi aktif [S5].
2. Asset and Identity Manager untuk menambah sumber (CSV, LDAP, cloud) dan mengecek status merge [S3]. Komunitas melaporkan kegagalan parsing CSV bisa terjadi diam-diam [S6], jadi selalu verifikasi dengan bagian 4.2.
3. Data Model Audit untuk akselerasi [S2].

## 5. Lab praktik

1. Jalankan bagian 4.1 (atau buka Settings > Data models). Catat status dan ukuran akselerasi Authentication dan Endpoint.
2. Buat `lab_assets.csv` (fiktif) dengan kolom `ip,mac,nt_host,dns,owner,priority,category,bunit,is_expected`. Isi untuk VM-VM lab-mu (mis. DC lab `priority=critical`, workstation `medium`).
3. Buat `lab_identities.csv` (fiktif) dengan kolom `identity,first,last,email,priority,bunit,category,watchlist,startDate,endDate`. Sertakan satu akun "mantan karyawan" dengan `endDate` di masa lalu.
4. **Dengan ES:** daftarkan kedua file di Asset and Identity Manager, tunggu merge, lalu verifikasi dengan bagian 4.2.
   **Tanpa ES:** buat automatic lookup (bagian 4.5).
5. Di VM Windows lab, login dengan akun "mantan karyawan" (gagal dan berhasil). Cari event 4624/4625 dan pastikan field enrichment muncul.
6. Jalankan bagian 4.3 dan 4.4. Hitung persentase host unknown.
7. Tulis deteksi sederhana: "login sukses oleh identitas dengan endDate < hari ini". Uji dulu dengan `makeresults` (Day 04).

**Hasil yang sebaiknya tersimpan:**
- Status akselerasi tercatat.
- Lookup aset/identitas fiktif aktif (ES atau automatic lookup).
- Event login lab diperkaya dengan prioritas dan konteks identitas.
- Persentase aset unknown dihitung.
- Deteksi "akun berakhir masih login" teruji.

**Variasi tantangan:** tambahkan subnet ke daftar aset dengan notasi CIDR (mis. `10.66.0.0/16`, `category=lab`), lalu pastikan IP tunggal di subnet itu ikut diperkaya. Di ES ini lewat `asset_lookup_by_cidr` [S3]; tanpa ES, lewat lookup definition dengan match type CIDR (Day 04).

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Field `src_*`/`dest_*` tidak muncul | Korelasi nonaktif/selektif untuk sourcetype itu; event hanya punya `host` | Correlation setup [S5]; normalisasi `src`/`dest`/`dvc` (Day 09) |
| Banyak aset "unknown" | Daftar aset tidak lengkap; format nama berbeda (FQDN vs NetBIOS) | Lengkapi `dns`, `nt_host`; tambahkan CIDR |
| Lookup gabungan kosong setelah unggah CSV | Kegagalan parsing diam-diam; format kolom salah | Cek isi `asset_lookup_by_*`; log identity manager [S3]; `[komunitas]` laporan kegagalan diam-diam [S6] |
| `asset_lookup_by_cidr` kosong | Tidak ada entri CIDR/rentang di sumber | Tambahkan entri CIDR. `[komunitas]` thread lama (ES 6) [S6], cek di ES 8 |
| Akselerasi tidak selesai | Model terlalu luas; batas waktu summarization | Allowlist index (Day 09); pantau Data Model Audit |
| Prioritas notable/finding tidak sesuai | Prioritas aset/identitas salah atau kosong | Perbaiki data sumber A&I; cek matriks urgensi (Day 20) |

## 7. Kesalahan umum dan jebakan

- Menganggap A&I "sekali isi selesai". Data aset dan identitas basi dengan cepat (karyawan keluar, IP DHCP berpindah). Butuh sumber otomatis (AD/LDAP, CMDB, Exposure Analytics) [S3].
- Mengandalkan field `host` untuk enrichment. ES 8 tidak lagi mengorelasikan `host`/`orig_host` secara otomatis [S5].
- Mematikan korelasi demi performa tanpa memahami dampaknya pada detection [S5].
- Akselerasi summary range "All time" tanpa kebutuhan. Boros disk dan waktu.
- Tidak memantau merge A&I. Kegagalan bisa diam-diam [S6].
- `[komunitas]` Thread Splunk Community tentang `assets_by_cidr` kosong dan error merge kebanyakan dari era ES 6.x [S6]. Polanya (format IP/CIDR, entri dummy) mungkin tidak berlaku lagi, cek di ES 8.

## 8. Catatan terkini

- **ES 8.x:** Exposure Analytics entity discovery menjadi sumber A&I yang direkomendasikan [S3]. Ini perubahan dibanding era ES 7 yang mengandalkan lookup manual dan LDAP.
- **ES 8.x:** korelasi tidak lagi otomatis terhadap `host`/`orig_host` [S5].
- **CIM 6.4.0 (Feb 2026):** menambah field unit bisnis di Data Access untuk mendukung aset/identitas (Day 09).
- Istilah ES 8: *risk object* menjadi entity (Day 06). Dokumentasi A&I tetap memakai "asset" dan "identity" untuk daftar sumbernya.

## 9. Cheat sheet

```
ACCEL   summary tsidx di indexer | ~5 menit | summary range | default OFF (CIM) | ES enforce | Data Model Audit
        | rest /services/admin/summarization by_tstats=t  (status, size), perlu dicek
A&I     sumber: Exposure Analytics (utama) | CSV | LDAP/AD | cloud
        alur: collect -> lookup -> definition -> Asset and Identity Manager -> merge (identity manager) -> verify
        hasil: asset_lookup_by_str | asset_lookup_by_cidr | identity_lookup_expanded
ASET    ip mac nt_host dns | owner priority bunit category pci_domain | is_expected should_timesync should_update requires_av | asset_tag
IDENT   identity (konvensi) first last email managedBy | priority bunit category watchlist startDate endDate | identity_tag
KORELASI src/dest/dvc -> aset ; user/src_user -> identitas ; output berprefiks: src_priority, dest_category, user_bunit...
        BUKAN host/orig_host ; Configure > All configurations > Assets and identities > Correlation setup (all/selective/off)
PAKAI   prioritas triage | risk scoring entity | konteks investigasi | sinyal (endDate lewat, is_expected=false)
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Accelerate data models (KM Manual 10.4; lihat Day 01) | https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.4/use-data-summaries-to-accelerate-searches/accelerate-data-models | primer | diakses 2026-10-07 | Tinggi |
| S2 | Set up the Splunk CIM Add-on (enforcement ES, Data Model Audit; lihat Day 09) | https://help.splunk.com/en/data-management/common-information-model/6.2/introduction/set-up-the-splunk-common-information-model-add-on | primer | diakses 2026-10-07 | Tinggi |
| S3 | ES 8.7: Add asset and identity data to Splunk Enterprise Security | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/asset-and-identity-management | primer | diakses 2026-10-07 | Tinggi. Sumber, alur, merge, lookup hasil |
| S4 | ES 8.7: Asset and identity fields after processing | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/asset-and-identity-validation/asset-and-identity-fields-after-processing-in-splunk-enterprise-security | primer | diakses 2026-10-07 | Tinggi. Field dan pemrosesan |
| S5 | ES 8.7: Configure asset and identity correlation | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/asset-and-identity-validation/configure-asset-and-identity-correlation-in-splunk-enterprise-security | primer | diakses 2026-10-07 | Tinggi. Field korelasi, menu, host tidak dikorelasikan |
| S6 | Splunk Community: assets_by_cidr not populating; A&I merge issues; merge errors | https://community.splunk.com/t5/Splunk-Enterprise-Security/Why-is-the-assets-by-cidr-csv-lookup-file-not-populating-during/m-p/513370 | komunitas | sebagian era ES 6 (>3 tahun) | Rendah-sedang |

**Catatan sumber:** rincian format lookup aset/identitas (daftar nilai priority, format tanggal), matriks urgensi, dan Exposure Analytics belum dirujuk ke halaman dokumentasi khusus; cek di dokumentasi ES 8.7 bagian asset and identity. Endpoint REST summarization perlu diuji di instance-mu. Thread komunitas [S6] sebagian besar dari era ES 6, jadi polanya mungkin tidak berlaku di ES 8.
