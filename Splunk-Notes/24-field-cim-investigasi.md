---
day: 24
title: 'Field CIM untuk investigasi: Authentication, Network Traffic, Endpoint, Web, DNS, Intrusion Detection'
researched_on: 2026-10-10
versions_checked: Splunk CIM 6.4 (halaman referensi data model Authentication, Network Traffic, Endpoint, Web, Network Resolution (DNS), Intrusion Detection); Splunk Enterprise 10.6; ES 8.7
---

# Day 24: Field CIM untuk investigasi

Cakupan: field CIM yang paling sering dipakai untuk pivot investigasi di enam data model utama, arti `src` dan `dest` per model, format nilai yang menggagalkan pivot, dan field enrichment aset/identitas.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- menyebut field kunci dan nilai yang diharapkan untuk data model Authentication, Network Traffic, Endpoint, Web, Network Resolution, dan Intrusion Detection.
- menulis `tstats` ke setiap model dengan nama dataset/objek yang benar.
- melakukan pivot investigasi lintas model memakai field bersama (`src`, `dest`, `user`), bukan nama field vendor.
- mengenali field yang tidak boleh diisi manual karena berasal dari korelasi aset/identitas.

## 2. Konteks singkat

Day ini adalah hasil konkret dari Day 23 dan 26. Setelah data ternormalisasi, kamu bisa berpikir dalam field CIM. Pertanyaan "IP 10.0.5.23 ini melakukan apa saja?" dijawab dengan satu kosakata di semua sumber: `src=10.0.5.23` di Network Traffic, Web, DNS, dan IDS; host terkait di `dest` Endpoint; user di Authentication.

Begitulah cara analyst ES bekerja sehari-hari. Yang membedakan cepat dan lambat adalah hafal field mana ada di model mana, beserta nilai standarnya.

## 3. Konsep inti

### 3.1 Field bersama yang menjadi poros pivot

| Field | Arti umum | Ada di |
|---|---|---|
| `src` | Sumber aktivitas (klien/peminta) | Authentication, Network Traffic, Web, DNS, IDS |
| `dest` | Tujuan/target aktivitas | Semua model di atas, plus Endpoint (host tempat proses berjalan) |
| `user` | Akun yang melakukan/terlibat | Authentication, Endpoint, Web, Network Traffic |
| `action` | Hasil/tindakan, nilai berbeda per model | Hampir semua model |
| `app` | Aplikasi/protokol | Authentication, Network Traffic |
| `dvc` | Perangkat yang melaporkan event | Network Traffic, IDS |
| `vendor_product` | Sumber vendor | Banyak model |

Field enrichment seperti `src_bunit`, `dest_category`, dan `src_priority` tidak boleh diisi manual oleh pembuat add-on. Field ini disediakan otomatis oleh korelasi aset/identitas [S5] (lihat Day 26).

### 3.2 Per data model

Authentication (dataset root `Authentication`, tag `authentication`) [S1]:
- `action`: `success`, `failure`, `pending`, `error`
- `app` (mis. `ssh`, `win:local`), `src`, `dest`, `user`, `src_user` (eskalasi privilege), `signature_id`, `authentication_method`, `authentication_service`, `reason_id`
- tstats: `from datamodel=Authentication.Authentication`, field `Authentication.<field>`

Network Traffic (dataset `All_Traffic`, tag `network` + `communicate`) [S2]:
- `action`: `allowed`, `blocked`, `teardown`
- `transport`: `icmp`, `tcp`, `udp` (huruf kecil); `protocol` = protokol layer 3
- `src`, `src_ip`, `src_port`, `dest`, `dest_ip`, `dest_port` (numerik), `app`, `bytes`, `bytes_in`, `bytes_out`, `packets`, `direction` (`inbound`/`outbound`), `dvc`, `rule`, `user`, `session_id`, `duration`
- tstats: `from datamodel=Network_Traffic.All_Traffic`, field `All_Traffic.<field>`

Endpoint (lima dataset) [S3]:
- **Processes**: model ini mencatat peluncuran proses, bukan proses yang sedang berjalan [S3]. Field-nya dikelompokkan menurut pemakaian:
  - identitas proses: `process` (command line lengkap), `process_name`, `process_path`, `process_exec`, `process_id`, `process_guid`, `process_hash`, `original_file_name`, `process_current_directory`, `process_integrity_level`;
  - induk: `parent_process` (command line induk), `parent_process_name`, `parent_process_path`, `parent_process_exec`, `parent_process_id`, `parent_process_guid`;
  - konteks: `user`, `user_id`, `dest` (host), `os`, `action`, `vendor_product`, plus `cpu_load_percent`, `mem_used`, `loaded_file` yang jarang terisi.
- **Filesystem**: `file_name`, `file_path`, `file_hash`, `file_size`, `file_create_time`, `file_modify_time`, `file_access_time`, `file_acl`, `user`, `dest`, serta `process_guid`, `process_id`, dan `image` untuk menghubungkan file ke proses pembuatnya. Nilai `action`: `created`, `modified`, `deleted`, `read`, `acl_modified` [S3].
- **Registry**: `registry_hive`, `registry_path`, `registry_key_name`, `registry_value_name`, `registry_value_data`, `registry_value_text`, `registry_value_type`, `status`, `user`, `dest`, `process_guid`, `process_id`, `image`. Nilai `action`: `created`, `modified`, `deleted`, `read` [S3].
- **Services**: `service_name`, `service`, `service_path`, `service_exec`, `service_hash`, `service_dll`, `service_dll_path`, `start_mode`, `status`, `user`, `dest`, ditambah field tanda tangan (`service_signature_verified`, `service_dll_signature_verified`) [S3].
- **Ports**: `dest_port`, `transport`, `dest`, `user`, `state`
- tstats: `from datamodel=Endpoint.Processes`, field `Processes.<field>`; analog untuk `Endpoint.Filesystem` dengan field `Filesystem.*`, dan seterusnya. Cek nama objek tiap dataset.

Web (dataset Web, plus Proxy dan Storage; tag `web`) [S4]:
- `url`, `uri_path`, `uri_query`, `url_domain`, `site`, `http_method`, `status` (kode HTTP), `http_user_agent`, `http_referrer`, `http_content_type`, `bytes_in`, `bytes_out`, `src`, `dest`, `dest_port`, `user`, `action`, `category`, `cookie`
- tstats: `from datamodel=Web.Web`, field `Web.<field>`; dataset Proxy, cek path `nodename`.

Network Resolution (DNS) (tag `network`, `resolution`, `dns`) [S5]:
- `query`, `query_type`, `record_type`, `reply_code`, `reply_code_id`, `answer`, `message_type` (`Query`/`Response`), `transaction_id`, `transport`, `src`, `dest`, `ttl`
- `reply_code` memakai nama kode DNS seperti `NoError`, `FormErr`, `ServFail`, `NXDomain`, `Refused`; `reply_code_id` adalah angkanya (0 = NoError, 1 = FormErr, 2 = ServFail, 3 = NXDomain) [S5]. Lonjakan `NXDomain` dari satu `src` adalah petunjuk klasik malware dengan domain generation algorithm.
- `record_type` berisi jenis record (`A`, `AAAA`, `MX`, `NS`, `PTR`, `TXT`). Banyak query `TXT` ke satu domain layak dicurigai sebagai tunneling.
- tstats: `from datamodel=Network_Resolution.DNS`, field `DNS.<field>`

Intrusion Detection (dataset IDS_Attacks, tag `ids` + `attack`) [S6]:
- `action` (allowed/blocked), `signature`, `signature_id`, `severity` (`critical`/`high`/`medium`/`low`/`informational`), `category`, `ids_type` (`network`/`host`/`application`/`wireless`), `dvc`, `src`, `dest`, `transport`, `user`, `vendor_product`
- tstats: `from datamodel=Intrusion_Detection.IDS_Attacks`, field `IDS_Attacks.<field>`

### 3.3 Arti "src" dan "dest" per konteks

Ini sumber kesalahan yang paling sering:
- Di Authentication: `src` = asal login (IP/host klien), `dest` = sistem yang dimasuki.
- Di Endpoint.Processes: `dest` = host tempat proses berjalan. Tidak ada "sumber" jaringan.
- Di Network Traffic: `src` = sisi yang memulai koneksi (klien), `dest` = sisi remote.
- Di Web (proxy): `src` = klien internal, `dest` = server web. `url_domain`/`site` = nama situs.

Jadi, untuk melacak "host X", cari `src=X` di jaringan/web/DNS dan `dest=X` di Endpoint/Authentication (sebagai target).

### 3.4 Kenapa nilai standar penting

Detection lintas vendor memfilter nilai, misalnya `action="blocked"` atau `severity IN ("critical","high")`. Bila TA vendor menghasilkan `action=deny` atau `severity=5`, detection menjadi buta (Day 23). Halaman referensi CIM juga menandai field yang diwajibkan dan direkomendasikan untuk pengujian add-on (pytest-splunk-addon) [S2][S5][S6]. Ini indikator field mana yang paling bisa diandalkan tersedia.

### 3.5 Field enrichment aset dan identitas

Field dengan akhiran `_priority`, `_category`, `_bunit`, `_is_expected`, `_requires_av`, `_should_timesync`, dan `_should_update` (mis. `src_priority`, `dest_category`, `user_bunit`) bukan berasal dari log. Field ini ditambahkan saat search oleh korelasi aset dan identitas ES: nilai `src`, `dest`, atau `user` dicocokkan ke lookup aset dan identitas, lalu atributnya ditempelkan ke event [S3][S5]. Karena itu:

- pembuat add-on tidak boleh mengisi field ini, karena nilainya akan bertabrakan dengan hasil korelasi;
- bila field ini kosong, masalahnya ada di daftar aset/identitas atau pada format `src`/`dest`/`user` yang tidak cocok dengan daftar itu, bukan di TA;
- di investigasi, field ini menjawab pertanyaan "seberapa penting host atau akun ini" tanpa kamu harus membuka CMDB. `dest_priority=critical` dan `dest_category=domain_controller` mengubah urgensi finding yang sama secara drastis.

Di Splunk Enterprise tanpa ES, efek serupa bisa ditiru dengan `lookup` aset buatan sendiri setelah `stats` (Day 12).

### 3.6 Format nilai yang menggagalkan pivot

Pivot lintas model hanya bekerja bila nilai field ditulis dengan format yang sama. Kegagalan yang paling sering ditemui:

| Field | Variasi yang muncul di data | Akibat | Cara menangani |
|---|---|---|---|
| `user` | `CORP\alice`, `alice@corp.example`, `alice`, `ALICE` | `user="alice"` tidak menemukan event Windows atau Azure AD | Cari dengan wildcard sementara (`*alice*`), lalu normalisasi di TA atau pakai identitas ES yang menyimpan beberapa format |
| `dest`/`src` | Nama pendek `WIN-LAB01`, FQDN `win-lab01.corp.example`, IP | Pivot dari Network Traffic (IP) ke Endpoint (hostname) gagal | Pakai daftar aset yang memetakan IP, nama, dan FQDN ke satu entitas; di lab, cek DHCP atau DNS untuk menerjemahkan |
| `src` vs `src_ip` | Sebagian TA hanya mengisi `src_ip` | Detection berbasis `src` buta | Pastikan TA membuat alias `src` (Day 23) |
| `user` di Authentication Windows | Event klasik memuat akun Subject dan akun target sekaligus | `user` bisa menjadi multivalue | Periksa `mvcount(user)`; pilih akun target untuk pertanyaan "siapa yang login" |
| `action` | `success` di satu TA, `Success` atau `succeeded` di TA lain | Filter persis gagal | Bagian 4.4 untuk menemukan nilai non-standar |

Prinsipnya: sebelum menyimpulkan "tidak ada aktivitas", pastikan nilai yang kamu cari ditulis sama seperti di data model. Satu `| tstats count from datamodel=... by <field>` pada rentang kecil cukup untuk melihat formatnya.

## 4. Contoh SPL dan langkah di ES

> Keluaran berlabel ilustrasi. Asumsi: data model terkait terisi dan, untuk `summariesonly=true`, terakselerasi (Day 25). Ganti `10.0.5.23` dengan IP yang relevan di lab-mu.

### 4.1 Pivot satu IP lintas model

```
| tstats summariesonly=false count from datamodel=Intrusion_Detection.IDS_Attacks
    where IDS_Attacks.src="10.0.5.23" OR IDS_Attacks.dest="10.0.5.23"
    by IDS_Attacks.signature IDS_Attacks.severity IDS_Attacks.action
| rename IDS_Attacks.* AS *
| eval model="IDS"
| append [
    | tstats summariesonly=false count sum(All_Traffic.bytes_out) AS bytes_out from datamodel=Network_Traffic.All_Traffic
        where All_Traffic.src="10.0.5.23" by All_Traffic.dest All_Traffic.dest_port All_Traffic.action
    | rename All_Traffic.* AS * | eval model="Network_Traffic" ]
| append [
    | tstats summariesonly=false count from datamodel=Network_Resolution.DNS
        where DNS.src="10.0.5.23" by DNS.query
    | rename DNS.* AS * | eval model="DNS" ]
| append [
    | tstats summariesonly=false count from datamodel=Web.Web
        where Web.src="10.0.5.23" by Web.url_domain Web.http_method Web.status
    | rename Web.* AS * | eval model="Web" ]
| table model signature severity action dest dest_port bytes_out query url_domain http_method status count
```

- Satu IP, empat model, satu kosakata (`src`).
- `summariesonly=false` dipakai karena ini investigasi, dan kelengkapan lebih penting dari kecepatan (Day 25).
- `append` cocok untuk beberapa subsearch kecil seperti ini (Day 14).

Keluaran ilustrasi (dipotong):

```
model            signature                     severity  action   dest           dest_port  query                 url_domain         count
IDS              ET POLICY ... (contoh)        medium    allowed  ...                                                                3
Network_Traffic                                          allowed  198.51.100.7   443                                                 41
DNS                                                                                         update-check.example                      41
Web                                                                                                               update-check.example 39
```

**Cara membaca hasil:** konsistensi antara query DNS, koneksi 443, dan request Web ke domain yang sama, dengan frekuensi serupa, mengarahkan ke kemungkinan beaconing. Lanjutkan dengan analisis interval (Day 39) dan cek host di Endpoint.

### 4.2 Dari host ke proses: siapa yang membuat koneksi itu?

```
| tstats summariesonly=false count values(Processes.process) AS cmd from datamodel=Endpoint.Processes
    where Processes.dest="WIN-LAB01" earliest=-24h
    by Processes.user Processes.parent_process_name Processes.process_name
| rename Processes.* AS *
| sort - count
```

- `Processes.dest` = host tempat proses berjalan (bagian 3.3).
- `values(Processes.process)` = command line lengkap.
- Untuk menghubungkan koneksi jaringan dengan proses, perlu data yang mencatat proses pemilik koneksi (mis. Sysmon EID 3 dengan `Image`). Itu tersedia di raw event, tidak selalu di Network Traffic, cek pemetaan Sysmon EID 3 ke CIM di TA Sysmon versi-mu.

### 4.3 Dari user ke aktivitas login

```
| tstats summariesonly=false count min(_time) AS first max(_time) AS last
    from datamodel=Authentication.Authentication
    where Authentication.user="alice" earliest=-7d
    by Authentication.action Authentication.src Authentication.dest Authentication.app
| rename Authentication.* AS *
| convert ctime(first) ctime(last)
| sort - last
```

**Cara membaca hasil:** cari `src` yang tidak biasa untuk user ini, `app` yang tidak biasa (mis. RDP pada user non-admin), dan rangkaian failure lalu success (Day 13).

### 4.4 Nilai field yang tidak standar: cek kualitas cepat

```
| tstats count from datamodel=Network_Traffic.All_Traffic by All_Traffic.action All_Traffic.transport sourcetype
| rename All_Traffic.* AS *
| where NOT in(action, "allowed","blocked","teardown") OR NOT in(transport, "tcp","udp","icmp")
```

- Menampilkan sourcetype yang nilainya tidak sesuai harapan CIM [S2].
- **Cara membaca hasil:** setiap baris adalah calon perbaikan TA (Day 23).

### 4.5 Studi kasus fiktif: dari alert IDS ke akun yang disalahgunakan

Skenario lab fiktif: IDS memberi alert `severity=high` untuk `src=10.0.5.23` dengan signature yang menunjukkan trafik C2 generik ke `198.51.100.7`. Urutan pivot dan pertanyaan yang dijawab di setiap langkah:

1. **IDS (bagian 4.1, model IDS):** alert hanya muncul tiga kali, `action=allowed`. Artinya trafik tidak diblokir, jadi perlu memastikan apakah ada sesi yang berlangsung.
2. **Network Traffic:** 41 koneksi ke `198.51.100.7:443` selama 6 jam, `bytes_out` kecil dan seragam. Pola kecil dan teratur lebih cocok dengan beaconing daripada browsing.
3. **DNS:** `src=10.0.5.23` me-resolve `update-check.example` dengan jumlah query yang hampir sama dengan jumlah koneksi. Domain ini menjadi observable kedua.
4. **Web:** request `GET` ke `update-check.example` dengan `http_user_agent` yang tidak cocok dengan browser yang terpasang di host.
5. **Endpoint (bagian 4.2):** host dengan IP itu adalah `WIN-LAB01`. Di jam pertama koneksi, ada proses `rundll32.exe` dengan induk `winword.exe` yang dijalankan `CORP\bob`.
6. **Authentication (bagian 4.3):** akun `bob` login dari `WIN-LAB01` ke dua server lain setelah jam itu, padahal biasanya hanya ke file server.

**Cara membaca rangkaian ini:** setiap model menjawab satu pertanyaan, dan field bersama (`src`, `dest`, `user`) menjadi benang yang menghubungkannya. Perhatikan pergantian peran field: IP yang menjadi `src` di jaringan berubah menjadi `dest` (sebagai hostname) di Endpoint, lalu user dari Endpoint menjadi `user` di Authentication. Kesimpulan sementara adalah host terinfeksi lewat dokumen dan akun `bob` mungkin disalahgunakan untuk pergerakan lateral. Langkah berikutnya adalah isolasi host dan reset kredensial, yang dibahas di Day 34.

**Kapan rangkaian ini putus:** bila IP di jaringan tidak bisa diterjemahkan ke hostname (bagian 3.6), atau Endpoint tidak memuat data proses untuk host itu. Catat celah seperti ini sebagai temuan kualitas data, bukan hanya sebagai hambatan investigasi.

### 4.6 Di ES (generik)

- Dashboard investigasi dan panel konteks entitas di ES dibangun di atas field ini. Ketika finding menampilkan `src`, `dest`, `user`, field itulah titik pivotnya. Jalur menu bervariasi di ES 8.x, cek (Day 31-32).
- Field action seperti drilldown sering menghasilkan search berbasis data model yang mirip bagian 4.1.

## 5. Lab praktik

1. Untuk setiap model di bagian 3.2 yang terisi di lab-mu, jalankan `| tstats count from datamodel=<Model>.<Dataset> by sourcetype`. Catat model kosong.
2. Jalankan bagian 4.4 untuk Network Traffic, dan versi serupa untuk Authentication (`action`) serta IDS (`severity`). Daftar ketidaksesuaian.
3. Di VM Windows lab: buka browser ke situs uji, jalankan `nslookup` ke domain uji, dan login RDP gagal/sukses. Lalu pivot dengan bagian 4.1-4.3 memakai IP/host/user VM tersebut.
4. Buat kartu field pribadi: satu halaman berisi model, dataset, field kunci, dan nilai standar (ringkas bagian 3.2).
5. Jelaskan dalam 3 kalimat arti `dest` di Endpoint vs di Network Traffic.
6. Cari format `user` yang berbeda di lab-mu: `| tstats count from datamodel=Authentication.Authentication by Authentication.user sourcetype`. Catat format per sourcetype dan tentukan format mana yang akan kamu jadikan acuan.
7. Ulangi studi kasus bagian 4.5 dengan aktivitas lab-mu sendiri dari langkah 3, lalu tulis rangkaian pivotnya dalam enam baris seperti contoh.

**Hasil yang sebaiknya tersimpan:**
- Daftar model terisi/kosong di lab.
- Laporan nilai non-standar.
- Hasil pivot satu IP lintas minimal 3 model.
- Kartu field selesai.
- Tabel format `user` per sourcetype.
- Rangkaian pivot tertulis dari aktivitas lab-mu.

**Variasi tantangan:** buat satu dashboard/report pivot dengan input token `ip` yang menjalankan bagian 4.1. Uji dengan 3 IP berbeda.

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| `tstats` model X kosong | Tidak ada TA/tag; model tidak relevan untuk data lab | `stats count by tag` pada sourcetype (Day 23) |
| Pivot `src` tidak menemukan apa pun di Endpoint | Di Endpoint, host ada di `dest` | Gunakan `Processes.dest` (bagian 3.3) |
| `action` bernilai `deny`/`accept` | TA tidak menormalkan nilai | Perbaiki normalisasi (Day 23) [S2] |
| Nama objek salah (`Network_Traffic.Network_Traffic`) | Dataset root berbeda nama | Gunakan `All_Traffic`, `IDS_Attacks`, `DNS`, `Processes` [S2][S3][S5][S6] |
| Field `src_priority` kosong | Korelasi A&I tidak aktif atau aset tidak dikenal | Day 26 |

## 7. Kesalahan umum dan jebakan

- Menganggap `src`/`dest` bermakna sama di semua model (bagian 3.3).
- Menulis detection dengan nilai vendor (mis. `action=deny`) alih-alih nilai CIM.
- **Salah nama dataset root di `tstats`**: `All_Traffic`, `IDS_Attacks`, `DNS`, bukan nama model [S2][S5][S6].
- Mengisi field enrichment A&I secara manual di TA [S5].
- Mengharapkan Endpoint.Processes menampilkan proses yang sedang berjalan. Model ini tentang peluncuran proses [S3].
- Menyimpulkan "tidak ada aktivitas" padahal formatnya berbeda (`CORP\alice` vs `alice`) (bagian 3.6).
- Mengabaikan `reply_code` di DNS. Query yang gagal (`NXDomain`) sering lebih menarik daripada yang berhasil.

## 8. Catatan terkini

- CIM 6.4 (Feb 2026) menambah beberapa field di Network Traffic dan Endpoint (Day 23), cek field baru apa saja dari release notes.
- Web data model mencakup dataset Storage (operasi cloud storage) di samping Web dan Proxy [S4]. Ini relevan untuk exfiltration ke cloud.
- Referensi CIM kini menandai field yang dipakai pytest-splunk-addon sebagai wajib/direkomendasikan [S2][S5][S6], yang berguna untuk menilai kualitas TA.

## 9. Cheat sheet

```
POROS     src | dest | user | action (nilai per model!) | app | dvc | vendor_product
          enrichment otomatis (jangan isi manual): src_priority dest_category user_bunit ...
AUTH      Authentication.Authentication  action=success|failure|pending|error ; src dest user src_user app signature_id
NETWORK   Network_Traffic.All_Traffic    action=allowed|blocked|teardown ; transport=tcp|udp|icmp ; src(_ip,_port) dest(_ip,_port) bytes_in/out packets direction dvc rule
ENDPOINT  Endpoint.Processes (process, process_name, parent_process_name, process_id, user, dest=host)
          .Filesystem (file_name,file_path,file_hash,action) .Registry (registry_path,key,value_name,value_data) .Services (service_name,path,start_mode,status) .Ports
WEB       Web.Web (+Proxy, Storage)  url uri_path uri_query url_domain site http_method status http_user_agent http_referrer bytes_in/out src dest user category
DNS       Network_Resolution.DNS     query query_type record_type reply_code answer message_type=Query|Response src dest ttl
IDS       Intrusion_Detection.IDS_Attacks signature signature_id severity=critical..informational ids_type=network|host|application|wireless action dvc src dest
MAKNA     Endpoint dest = host proses ; Network/Web/DNS src = klien ; Auth src = asal login, dest = sistem target
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | CIM 6.4: Authentication | https://help.splunk.com/en/data-management/common-information-model/6.4/data-models/authentication | primer | diakses 2026-10-07 | Tinggi |
| S2 | CIM 6.4: Network Traffic | https://help.splunk.com/en/data-management/common-information-model/6.4/data-models/network-traffic | primer | diakses 2026-10-07 | Tinggi |
| S3 | CIM 6.4: Endpoint | https://help.splunk.com/en/data-management/common-information-model/6.4/data-models/endpoint | primer | diakses 2026-10-07 | Tinggi. Dataset, field, dan nilai `action` Filesystem/Registry |
| S4 | CIM 6.4: Web | https://help.splunk.com/en/data-management/common-information-model/6.4/data-models/web | primer | diakses 2026-10-07 | Tinggi |
| S5 | CIM 6.4: Network Resolution (DNS) | https://help.splunk.com/en/data-management/common-information-model/6.4/data-models/network-resolution-dns | primer | diakses 2026-10-07 | Tinggi |
| S6 | CIM 6.4: Intrusion Detection | https://help.splunk.com/en/data-management/common-information-model/6.4/data-models/intrusion-detection | primer | diakses 2026-10-07 | Tinggi |

**Catatan sumber:** path `nodename` untuk dataset Proxy dan Storage di Web, serta nama objek dataset Endpoint selain Processes saat dipanggil lewat `tstats`, perlu dicek di CIM versi lab-mu (`| datamodel Web` dan `| datamodel Endpoint` menampilkan strukturnya). Studi kasus di bagian 4.5 fiktif. Contoh variasi format `user` di bagian 3.6 berasal dari pola umum log Windows dan identitas cloud, bukan dari satu dokumen.
