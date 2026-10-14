---
day: 23
title: 'Praktik terbaik SIEM, CIM, dan data model: normalisasi saat search dengan eventtype, tag, alias, dan lookup'
researched_on: 2026-10-07
versions_checked: Splunk CIM Add-on 6.4.0 (4 Feb 2026; referensi data model CIM 6.4); panduan setup CIM (dok 6.2) dan normalisasi (dok 6.1); SA-cim_vladiator 2.1.0 (Jun 2026); Splunk Enterprise 10.6; ES 8.7
---

# Day 23: Praktik terbaik SIEM, CIM, dan data model

Cakupan: praktik terbaik SIEM dan konsep operasi dasar ES, interaksi CIM dengan data model.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- menjelaskan CIM sebagai skema saat search yang menormalkan data dari berbagai vendor, beserta alasan ES dan detection bergantung padanya.
- menyebut data model CIM utama, dan memilih model yang tepat untuk sebuah sumber berdasarkan tujuan event, bukan nama field.
- menjalankan alur normalisasi: eventtype, tag, field alias/extraction/calculated field, lookup, lalu validasi.
- memeriksa kepatuhan CIM sebuah sourcetype dengan `datamodel`, `tstats`, dan `fieldsummary`.
- merangkum praktik terbaik operasi SIEM yang paling sering menentukan di pekerjaan.

## 2. Konteks singkat

Day 25 memakai `tstats ... from datamodel=Authentication`, sedangkan Day 45 menunjukkan bahwa detection ESCU bergantung pada data model. Hari ini kita membahas kenapa semua itu bisa bekerja: CIM.

Tanpa CIM, setiap vendor punya nama field sendiri:
- Windows memakai `Account_Name`;
- Linux memakai `user`;
- Okta memakai `actor.alternateId`;
- firewall memakai `srcip`, `src_ip`, atau `source_address`.

Satu detection harus ditulis ulang untuk setiap vendor. CIM menyelesaikan ini dengan lapisan normalisasi di atas data mentah. Data mentah tidak diubah; yang ditambahkan adalah aturan baca [S1].

## 3. Konsep inti

### 3.1 Apa itu CIM

CIM adalah model semantik bersama yang diimplementasikan sebagai add-on (`Splunk_SA_CIM`). Isinya [S1]:
- kumpulan data model;
- dokumentasi;
- alat validasi;
- model aksi umum untuk alert action.

CIM adalah skema saat search: data dinormalisasi ketika dibaca, tanpa mengubah raw data. CIM disertakan bersama ES [S1].

Setiap data model berisi nama field dan tag yang mewakili "penyebut terkecil yang sama" untuk satu domain, misalnya autentikasi atau trafik jaringan [S1].

Data model di CIM 6.4. Navigasi referensi resmi menampilkan 26 entri, dua di antaranya deprecated [S2]:

| Domain | Data model |
|---|---|
| Identitas dan akses | Authentication, Data Access, Change |
| Endpoint | Endpoint, Malware, Updates, Inventory, Performance |
| Jaringan | Network Traffic, Network Resolution (DNS), Network Sessions, Intrusion Detection, Web, Email, Certificates |
| Data dan aplikasi | Data Loss Prevention, Databases, Interprocess Messaging, Java Virtual Machines (JVM) |
| Operasi keamanan | Alerts, Event Signatures, Vulnerabilities, Ticket Management, Splunk Audit Logs |
| Deprecated | Application State, Change Analysis |

CIM 6.4.0 (4 Feb 2026) menambahkan field unit bisnis di Data Access (untuk aset/identitas), serta beberapa field di Network Sessions, Network Traffic, dan Endpoint [S3].

**Catatan dokumentasi:** halaman CIM di help.splunk.com juga muncul dengan label versi 8.x di beberapa jalur (mis. jalur Splunk Cloud/Enterprise 8.5/8.6), padahal versi add-on terbaru adalah 6.4.0. Ini kemungkinan karena dokumentasi mengikuti versi produk induk, perlu dicek. Yang penting adalah versi add-on CIM yang terpasang di instance Splunk-mu.

### 3.2 Bagaimana event "masuk" ke data model

Data model mendefinisikan constraint, yang umumnya berupa tag. Contoh: dataset Authentication menyaring event dengan `tag=authentication` (Day 25 [S3] di catatan Day 25). Event masuk ke model bila:
1. Eventtype cocok dengan event (eventtype adalah search tersimpan yang mengelompokkan event).
2. Eventtype itu diberi tag yang sesuai constraint (mis. `authentication`).
3. Field event bernama sesuai CIM (`user`, `src`, `dest`, `action`, ...), lewat extraction, field alias, atau calculated field (`EVAL-`).
4. Nilai field sesuai harapan. Contoh: `action` di Authentication harus `success`/`failure`/`pending`/`error`, bukan `Failed` atau `4625`. Untuk itu dipakai lookup atau `EVAL-`.

Referensi CIM mencantumkan nilai yang diharapkan, termasuk nilai yang diharapkan ES ("ES expects") dan nilai yang dipakai sebagai constraint ("Other") [S2]. Jika nilainya salah, event mungkin masuk ke model, tetapi detection yang memfilter `action="failure"` tidak akan menemukannya.

Biasanya semua ini sudah dikerjakan oleh Technology Add-on (TA) vendor (mis. Splunk Add-on for Microsoft Windows, for Sysmon, for Palo Alto). Tugasmu sebagai analyst/engineer adalah memverifikasi, dan menormalkan sendiri hanya bila TA tidak ada.

### 3.3 Alur normalisasi saat search (resmi)

Dokumentasi CIM menjabarkan langkah [S4]:
1. Ingest data apa adanya. Normalisasi terjadi saat search.
2. **Periksa data dalam konteks CIM:** tentukan data model berdasarkan tujuan event. Event login masuk Authentication walaupun field `app` juga ada di model lain. Jangan memaksa berdasarkan nama field [S4].
3. Konfigurasi tag lewat eventtype (Settings > Event types) [S4].
4. Verifikasi tag (lihat `tag::eventtype` di field picker) [S4].
5. **Normalisasi field:**
   - prioritaskan field yang direkomendasikan;
   - field alias (`FIELDALIAS-`);
   - extraction dengan nama persis sesuai CIM;
   - lookup untuk menambah atau menormalkan nilai (vendor, product, kode menjadi teks);
   - verifikasi [S4].
6. Validasi terhadap data model lewat Datasets/Pivot atau command `datamodel` [S4].
7. (Opsional) Perluas CIM dengan field kustom.
8. (Opsional) Paketkan sebagai add-on [S4].

### 3.4 Setup CIM: index constraint dan akselerasi

Halaman CIM Setup (Apps > Manage Apps > Set up untuk CIM, atau `/app/search/cim_setup`) mengatur per data model [S5]:
- **Indexes allowlist**: index yang dicari data model. Ini kunci performa (Day 25, Lantern [S6] di catatan Day 25).
- Tags allowlist.
- Accelerate, Summary range, Backfill range, Max summarization search time.

Fakta penting [S5]:
- Semua data model CIM non-aktif akselerasinya secara default.
- Akses setup membutuhkan capability `accelerate_datamodel` (CIM 4.12.0 ke atas).
- Jika ES terpasang, akselerasi dipaksakan (enforced) oleh ES. Perubahan hanya bertahan bila dilakukan lewat modular input *Data Model Acceleration Enforcement*, cek nama dan lokasi pengaturan di ES 8.x.
- Pantau dengan Data Model Audit [S5].

### 3.5 Praktik terbaik SIEM (rangkuman untuk 3.2)

1. Use case dan risiko menggerakkan koleksi data (Day 21).
2. Normalisasi ke CIM sebelum menulis detection lintas vendor. Validasi, jangan berasumsi.
3. Batasi index per data model dan aktifkan akselerasi hanya untuk model yang dipakai [S5].
4. **Waktu yang benar:** UTC, sinkron NTP, dan parsing timestamp yang benar (Day 21).
5. Konteks aset dan identitas untuk prioritas dan korelasi (Day 26).
6. Detection teruji dan terdokumentasi, dengan tuning lewat filter (Day 45, Day 36).
7. **Pantau kesehatan pipeline:** kesegaran data, skipped searches, status akselerasi (Day 14, Day 21).
8. Kurangi alert fatigue dengan pendekatan berbasis risiko (Day 35).

### 3.6 Enterprise vs ES

- CIM add-on gratis dan dapat dipakai di Splunk Enterprise tanpa ES. Kamu bisa membangun detection berbasis data model sendiri.
- ES bergantung pada CIM: dashboard, detection, risk, dan asset/identity membaca field CIM. ES juga memaksakan pengaturan akselerasi [S1][S5].

## 4. Contoh SPL dan langkah di ES

> Keluaran berlabel ilustrasi. Konfigurasi di bagian 4.4 adalah contoh fiktif untuk aplikasi lab.

### 4.1 Apakah sourcetype ini sudah diberi tag dan masuk model?

```
index=botsv1 sourcetype="WinEventLog:Security" (EventCode=4624 OR EventCode=4625) earliest=0
| stats count BY EventCode tag eventtype
```

- Menunjukkan tag dan eventtype yang melekat pada event logon. Hasil yang diharapkan: ada tag `authentication` (dan mungkin `success`/`failure`) dari TA Windows.
- **Jika tidak ada tag:** TA tidak terpasang atau eventtype tidak cocok, sehingga event tidak akan masuk Authentication.

### 4.2 Validasi nilai field CIM dengan tstats

```
| tstats count from datamodel=Authentication where sourcetype="WinEventLog:Security"
    by Authentication.action Authentication.app Authentication.signature_id
| rename Authentication.* AS *
```

- Periksa apakah `action` hanya bernilai `success`/`failure` (sesuai harapan CIM, Day 25).
- `signature_id` biasanya berisi kode event (mis. 4624/4625), cek pemetaan TA Windows.
- **Cara membaca hasil:** jika muncul `action=unknown` atau kosong, detection berbasis `action` akan bolong.

### 4.3 Melihat isi model langsung dengan datamodel + fieldsummary

```
| datamodel Authentication Authentication search
| search sourcetype="WinEventLog:Security"
| fieldsummary maxvals=5
| search field IN ("Authentication.user","Authentication.src","Authentication.dest","Authentication.action","Authentication.app")
| table field count distinct_count values
```

- `datamodel <model> <dataset> search`: menjalankan constraint dataset sebagai search. Ini pola validasi resmi; dokumentasi mencontohkan `| datamodel Authentication Successful_Authentication search | search sourcetype=linux_secure | table * | fieldsummary` [S4].
- `fieldsummary`: statistik per field (berapa yang terisi, nilai unik, contoh nilai).
- **Cara membaca hasil:** `count` kecil dibanding total event berarti banyak event tanpa field itu, alias ada celah normalisasi.
- Cek nama field hasil `datamodel` (dengan atau tanpa prefiks dataset) di versi-mu, dan apakah dataset `Successful_Authentication` ada di CIM yang kamu pakai (Day 25 mencatat perbedaan versi).

### 4.4 Menormalkan log aplikasi lab (fiktif) ke Authentication

Contoh raw event aplikasi internal "labportal":

```
2026-10-07T10:15:22Z labportal login result=FAILED username=alice client=10.0.5.23 server=portal01
```

Konfigurasi (contoh, di app/TA lab milikmu sendiri):

`eventtypes.conf`
```
[labportal_login]
search = sourcetype=labportal "login"
```

`tags.conf`
```
[eventtype=labportal_login]
authentication = enabled
```

`props.conf`
```
[labportal]
EXTRACT-labportal_fields = result=(?<lp_result>\w+)\s+username=(?<lp_user>\S+)\s+client=(?<lp_client>\S+)\s+server=(?<lp_server>\S+)
FIELDALIAS-lp_user = lp_user AS user
FIELDALIAS-lp_src = lp_client AS src
FIELDALIAS-lp_dest = lp_server AS dest
EVAL-action = case(lp_result=="SUCCESS","success", lp_result=="FAILED","failure", true(),"unknown")
EVAL-app = "labportal"
```

| Baris | Fungsi | Kenapa |
|---|---|---|
| eventtype `labportal_login` | Mengelompokkan event login | Tag melekat ke eventtype, bukan langsung ke sourcetype |
| tag `authentication` | Memenuhi constraint data model Authentication | Tanpa tag, event tidak masuk model |
| `EXTRACT-` | Ekstraksi dengan nama sementara `lp_*` | Bisa juga langsung bernama CIM [S4] |
| `FIELDALIAS-` | `lp_user` -> `user`, dst. | Pola alias resmi [S4] |
| `EVAL-action` | Normalisasi nilai `FAILED` -> `failure` | CIM mengharapkan nilai tertentu |
| `EVAL-app` | Mengisi field `app` | Membantu membedakan sumber di detection |

Validasi: jalankan bagian 4.2 dan 4.3 untuk `sourcetype=labportal`. Hasil yang diharapkan: `action` berisi success/failure dan `user`/`src`/`dest` terisi.
**Kapan gagal:**
- Konfigurasi diletakkan di app yang izinnya tidak global, sehingga tidak berlaku saat search dijalankan dari app lain.
- Urutan operasi search-time salah dipahami. Urutannya: `EXTRACT`, lalu `REPORT`, `KV_MODE`, `FIELDALIAS`, `EVAL`, dan terakhir `LOOKUP`. Artinya alias bisa merujuk field hasil `EXTRACT`, dan `EVAL-` bisa merujuk alias, tetapi `FIELDALIAS` tidak bisa merujuk field hasil `EVAL-`.
- Satu `EVAL-` merujuk field hasil `EVAL-` lain di stanza yang sama. Semua `EVAL-` dievaluasi bersamaan dari data sebelum EVAL, jadi rujukan seperti itu hasilnya kosong. Gabungkan logikanya ke satu ekspresi.

Cek urutan di atas dengan halaman "search-time operations sequence" di dokumentasi props.conf versi lab-mu.

### 4.5 Alat bantu kepatuhan CIM

- SA-cim_vladiator (komunitas, Splunkbase): mengidentifikasi field yang hilang dan nilai yang tidak sesuai harapan CIM. Versi 2.1.0 tercatat Juni 2026 [S7]; cocokkan dengan Splunkbase sebelum memasang.
- CIM Assessment Toolkit (Splunkbase) dan dashboard CIM Compliance Check di SSE [S7]. Keduanya membandingkan field dan tag data-mu dengan yang diharapkan data model; cek nama dan ketersediaannya di Splunkbase dan SSE versi-mu.

### 4.6 Di ES (generik)

- Halaman audit data model (Data Model Audit) menunjukkan status akselerasi dan ukuran [S5].
- Pengaturan akselerasi data model di ES di-enforce. Ubah lewat mekanisme ES, bukan hanya CIM Setup [S5], cek menu ES 8.x.

## 5. Lab praktik

1. Pasang Splunk CIM add-on di Splunk lab (gratis). Buka CIM Setup [S5]. Untuk Authentication dan Endpoint, isi Indexes allowlist dengan index lab-mu dan aktifkan akselerasi.
2. Jalankan bagian 4.1-4.3 untuk data Windows/Sysmon lab. Catat celah: field kosong dan nilai di luar harapan.
3. Buat sourcetype `labportal` dengan mengunggah file log fiktif berisi 20 baris (campuran SUCCESS/FAILED, beberapa user/IP) lewat Add Data.
4. Terapkan konfigurasi bagian 4.4 di app lab-mu (UI: Settings > Event types, Tags, Fields > Field aliases / Calculated fields, atau edit file `.conf` bila punya akses).
5. Validasi dengan bagian 4.2 dan 4.3. Lalu jalankan brute-force detection Day 25 bagian 4.2 dan pastikan `labportal` ikut terdeteksi tanpa mengubah detection. Inilah inti nilai CIM.
6. Dokumentasikan konfigurasimu sebagai "mini TA" (struktur folder: `default/eventtypes.conf`, `tags.conf`, `props.conf`).

**Hasil yang sebaiknya tersimpan:**
- CIM Setup dengan allowlist index dan akselerasi aktif.
- Laporan celah normalisasi untuk Windows/Sysmon lab.
- `labportal` muncul di Authentication dengan action success/failure.
- Detection Day 25 menangkap `labportal` tanpa modifikasi.

**Variasi tantangan:** tambahkan lookup `labportal_reasons.csv` yang memetakan kode error aplikasi ke field CIM `reason`, lalu pasang sebagai automatic lookup. Validasi dengan `fieldsummary`.

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Event tidak masuk data model | Tidak ada tag yang sesuai constraint | bagian 4.1; perbaiki eventtype/tag [S4] |
| Masuk model, tapi detection tidak fire | Nilai field tidak sesuai harapan (mis. `Failed`) | bagian 4.2; normalisasi nilai dengan `EVAL-`/lookup [S2][S4] |
| Field alias tidak muncul | Izin knowledge object (private/app), atau sourcetype salah | Share ke global/app; cek stanza |
| Akselerasi kembali ke setelan lama | ES meng-enforce pengaturan | Ubah lewat mekanisme enforcement ES [S5] |
| Data model lambat | Tanpa index allowlist | CIM Setup > Indexes allowlist [S5] |
| Validator menunjukkan 0% compliance padahal field ada | Konfigurasi validator, nama dataset, atau versi CIM | `[komunitas]` kasus serupa dilaporkan di Splunk Community [S7], perlu dicek |

## 7. Kesalahan umum dan jebakan

- Memilih data model berdasarkan nama field, bukan tujuan event [S4].
- Mengira field CIM saja cukup. Tag dan nilai yang benar sama pentingnya [S2].
- Menimpa field CIM dengan `eval` di search dan menganggap itu normalisasi. Itu hanya berlaku di satu search (Day 11).
- Akselerasi semua data model tanpa allowlist index. Mahal (Day 25, [S5]).
- Lupa bahwa ES meng-enforce akselerasi [S5].
- `[komunitas]` Banyak pertanyaan di Splunk Community berbentuk "cara membuat data CIM-compliant di ES" [S7]. Jawabannya hampir selalu: pakai TA vendor, lalu validasi tag dan field. Konsisten dengan dokumentasi [S4].

## 8. Catatan terkini

- **CIM 6.4.0 (Feb 2026)**: field unit bisnis baru di Data Access untuk aset/identitas, plus tambahan field di Network Sessions, Network Traffic, dan Endpoint [S3].
- Dokumentasi CIM kini memakai istilah allowlist (dulu whitelist) [S5].
- Alat validasi komunitas aktif diperbarui (SA-cim_vladiator 2.1.0, CIM Assessment Toolkit 2.10.0, keduanya tercatat Juni 2026) [S7]; versi ini perlu dicocokkan dengan Splunkbase.
- ES 8 menyelaraskan istilahnya dengan OCSF (Day 45). CIM tetap menjadi skema data model yang dipakai ES 8, cek hubungan CIM-OCSF di dokumentasi ES 8.

## 9. Cheat sheet

```
CIM = skema saat search (Splunk_SA_CIM): data model = field + tag (+ nilai yang diharapkan)
MASUK MODEL: eventtype -> tag (constraint) -> field CIM (EXTRACT/FIELDALIAS/EVAL) -> nilai benar (EVAL/lookup)
PILIH MODEL berdasarkan TUJUAN event (login -> Authentication), bukan nama field
ALUR: ingest -> tentukan DM -> eventtype+tag -> verifikasi tag -> alias/extract/lookup -> validasi (datamodel/Pivot) -> (extend) -> (package TA)
SETUP: Apps > Manage Apps > CIM Set up : Indexes allowlist | Tags allowlist | Accelerate | Summary/Backfill range | Max summarization time
       akselerasi CIM default OFF ; ES meng-enforce ; capability accelerate_datamodel
VALIDASI: index=.. sourcetype=.. | stats count by tag eventtype
          | tstats count from datamodel=DM where sourcetype=X by DM.action ...
          | datamodel DM Dataset search | search sourcetype=X | fieldsummary
DM 6.4: Authentication, Endpoint, Network_Traffic, Network_Resolution, Web, Email, Intrusion_Detection, Malware,
        Change, Data_Access, Vulnerabilities, Alerts, Certificates, DLP, Databases, Network_Sessions, Updates, Inventory,...
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Overview of the Splunk Common Information Model | https://help.splunk.com/en/data-management/common-information-model | primer | diakses 2026-10-07 | Tinggi. Halaman menampilkan label versi 8.7 (lihat catatan bagian 3.1) |
| S2 | CIM 6.4: How to use the CIM data model reference tables (daftar data model) | https://help.splunk.com/en/data-management/common-information-model/6.4/data-models | primer | diakses 2026-10-07 | Tinggi. Daftar model, "ES expects" |
| S3 | CIM 6.4: Release notes | https://help.splunk.com/en/data-management/common-information-model/6.4/introduction/release-notes-for-the-splunk-common-information-model-add-on | primer | 2026-02-04 | Tinggi |
| S4 | Use the CIM to normalize data at search time (dok 6.1) | https://help.splunk.com/en/data-management/common-information-model/6.1/using-the-common-information-model/use-the-cim-to-normalize-data-at-search-time | primer | diakses 2026-10-07 | Tinggi. Alur normalisasi, contoh konfigurasi |
| S5 | Set up the Splunk Common Information Model Add-on (dok 6.2) | https://help.splunk.com/en/data-management/common-information-model/6.2/introduction/set-up-the-splunk-common-information-model-add-on | primer | diakses 2026-10-07 | Tinggi. Allowlist, akselerasi, enforcement ES |
| S6 | Lantern: Managing data models in ES (lihat Day 25) | https://lantern.splunk.com/Security/Product_Tips/Enterprise_Security/Managing_data_models_in_Enterprise_Security | primer | diakses 2026-10-07 | Tinggi |
| S7 | SA-cim_vladiator (GitHub/Splunkbase), CIM Assessment Toolkit, Splunk Community "SA-cim validator showing 0% compliance", "How to make CIM compliant data in ES" | https://github.com/hire-vladimir/SA-cim_vladiator | komunitas | tanggal tidak tercatat | Rendah-sedang. Versi dan tanggal perlu dicocokkan dengan Splunkbase |

**Catatan sumber:** panduan normalisasi dan setup yang dirujuk adalah dokumentasi CIM 6.1/6.2 [S4][S5]; isinya diasumsikan masih berlaku untuk 6.4, jadi cek bila ada perbedaan menu. Urutan operasi search-time di props.conf belum dirujuk ke sumber primer di Day ini. Versi alat validasi komunitas [S7] perlu dicocokkan dengan Splunkbase.
