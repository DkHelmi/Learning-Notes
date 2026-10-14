---
day: 41
title: 'Adaptive response action: kapan dipakai dan cara mengonfigurasinya'
researched_on: 2026-10-10
versions_checked: Splunk ES 8.7 (Configure adaptive response actions for detections); ES 8.4 (Adaptive response action relays); Splunk CIM 6.x (common action model); Splunk Enterprise 10.6
---

# Day 41: Adaptive response action, kapan dan bagaimana

Cakupan: menentukan kapan memakai adaptive response action dan mengonfigurasinya sesuai kebutuhan.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- membedakan adaptive response (AR) untuk enrichment/pengumpulan bukti vs containment/remediasi, serta risikonya.
- memutuskan kapan AR dijalankan otomatis (dari detection) dan kapan ad hoc (oleh analyst), dengan matriks keputusan.
- mengonfigurasi AR di detection editor ES 8.7, menjalankannya ad hoc, dan memahami relay untuk menjalankan aksi dari Splunk Cloud ke on-prem.
- menjelaskan jalur AR kustom dan batas antara AR dan SOAR.

## 2. Konteks singkat

Day 31 memperkenalkan daftar AR bawaan. Hari ini fokusnya pada keputusan. Tindakan otomatis mempercepat respons. Tetapi tindakan yang salah, misalnya memblokir server produksi karena false positive, bisa lebih merugikan dari serangannya.

Dokumentasi ES menekankan nilai AR sebagai cara mengumpulkan informasi dan memulai tindakan sebelum investigasi dimulai, sehingga triage lebih cepat [S1][S2].

## 3. Konsep inti

### 3.1 Jenis AR berdasarkan tujuan

| Tujuan | Contoh bawaan ES 8.7 [S1] | Risiko jika salah | Cocok otomatis? |
|---|---|---|---|
| Membuat artefak kerja | Finding, Log an event, Create Splunk messages | Noise | Ya (inti detection) |
| Notifikasi | Send email, Send to Splunk Mobile | Alert fatigue | Ya, untuk severity tinggi saja |
| Enrichment/konteks | Nslookup, Nbtstat, Ping | Rendah (read-only) | Ya |
| Pengumpulan bukti | Stream Capture | Biaya/penyimpanan; privasi | Selektif |
| Intel | Add Threat Intelligence | IOC salah menyebar ke detection lain | Ad hoc/setelah verifikasi |
| Integrasi | Send to UBA, Output results to telemetry endpoint | Tergantung tujuan | Sesuai desain |
| Tindakan kustom | Run a script (dari `$SPLUNK_HOME/bin/scripts`) | Tinggi bila memodifikasi sistem | Hanya bila reversibel dan berkeyakinan tinggi |

Containment yang sebenarnya (isolasi host di EDR, nonaktifkan akun, blokir di firewall) biasanya datang dari AR app vendor di Splunkbase atau SOAR playbook (Day 42), bukan dari aksi bawaan, cek app AR vendor yang kamu pakai.

### 3.2 Kapan otomatis, kapan ad hoc: matriks keputusan

Pertimbangkan empat faktor:
1. Keyakinan (confidence) detection: berapa FP rate-nya (Day 34)?
2. **Reversibilitas:** bisa dibatalkan cepat?
3. **Blast radius:** apa dampaknya bila salah (server kritis vs laptop)?
4. **Kebijakan/legal:** apakah butuh persetujuan (mis. menonaktifkan akun eksekutif)?

| Keyakinan | Tindakan reversibel, dampak rendah | Tindakan berdampak tinggi/sulit dibatalkan |
|---|---|---|
| Tinggi (FP rendah, teruji) | Otomatis | Otomatis dengan guardrail (bukan aset kritis, ada batas jumlah) atau semi-otomatis (persetujuan di SOAR) |
| Sedang | Otomatis untuk enrichment; ad hoc untuk tindakan | Ad hoc oleh analyst |
| Rendah | Hanya enrichment/risk (RBA) | Jangan otomatis |

**Prinsip:** otomatisasi enrichment secara luas, sedangkan tindakan secara sempit. Gunakan konteks A&I (Day 26) sebagai guardrail, misalnya "jangan isolasi otomatis bila `dest_priority=critical`".

### 3.3 Mengonfigurasi AR

**Otomatis (di detection):** di detection editor, bagian Adaptive response actions: pilih aksi, lalu isi parameternya (mis. penerima email, field host untuk ping, nama skrip) [S1] (Day 36).

**Ad hoc (oleh analyst):** saat memeriksa finding di Mission Control, analyst menjalankan aksi yang tersedia [S1]. Di ES 7, ini dilakukan dari Incident Review [S2].

Relay (Splunk Cloud ke on-prem) [S3]:
- **Masalah:** ES di Splunk Cloud tidak boleh membuka akses langsung ke jaringan internal untuk menjalankan aksi.
- **Solusi:** aksi diantrekan di search head cloud, lalu heavy forwarder on-prem (relay) mengambil dan menjalankannya.
- **Komponen:** heavy forwarder dengan add-on Adaptive Response, modular action relay (input di HF), modular action worker (di search head cloud), dan API key yang cocok di kedua sisi. Saat membuat detection, pilih worker set.

**AR kustom:**
- Bisa dibangun sebagai alert action yang mematuhi common action model CIM. CIM add-on menyertakan model aksi umum untuk alert action (Day 23), cek panduan pembuatan terkini.
- Alat yang lazim dipakai adalah Splunk Add-on Builder, cek dukungan AR di versi Add-on Builder terkini.

**Hasil dan audit:** setiap eksekusi AR tercatat. Secara klasik, ES menyimpan hasil aksi di index `cim_modactions`, cek di ES 8.7. Hasil ini penting untuk akuntabilitas: siapa menjalankan apa, kapan, dan dengan hasil apa.

### 3.4 AR vs SOAR

| | Adaptive response | SOAR playbook |
|---|---|---|
| Lingkup | Satu aksi per eksekusi (atau beberapa aksi terpisah) | Alur multi-langkah dengan logika, percabangan, persetujuan |
| Tempat | Di ES (detection/finding) | Di platform SOAR, dipicu dari ES |
| Cocok untuk | Enrichment cepat, notifikasi, aksi sederhana | Respons kompleks, integrasi banyak alat, human-in-the-loop |

Detail SOAR di Day 42.

### 3.5 Enterprise vs ES

- **Splunk Enterprise:** alert action (email, webhook, skrip, app alert action). Konsep otomatis vs manual sama.
- **ES:** AR terintegrasi dengan finding, eksekusi ad hoc dari Mission Control, relay, dan pencatatan hasil.

### 3.6 Studi kasus fiktif: isolasi otomatis yang salah sasaran

Sebuah SOC memasang aksi isolasi host (dari app AR vendor EDR) secara otomatis pada detection "Suspicious Rundll32 Network Connection". Detection itu baru dua minggu aktif dan FP rate-nya belum pernah diukur. Pada Senin pagi, update agen backup memakai `rundll32.exe` untuk memanggil komponen yang menghubungi server backup. Dalam 20 menit, 46 host diisolasi, termasuk dua server aplikasi kasir.

Apa yang salah, dilihat dari matriks bagian 3.2:

- **Keyakinan:** rendah, karena belum ada data disposition (Day 34). Detection seperti ini seharusnya hanya mendapat enrichment atau output risk.
- **Reversibilitas:** isolasi bisa dibatalkan, tetapi tidak cepat untuk 46 host, dan butuh orang yang punya akses konsol EDR.
- **Blast radius:** tidak ada guardrail berbasis prioritas aset, sehingga server kritis ikut terkena.
- **Batas jumlah:** tidak ada pembatas "maksimal N aksi per jam". Pembatas sederhana akan menghentikan kejadian setelah host ketiga.

Perbaikan yang diambil: aksi isolasi dipindah ke SOAR dengan persetujuan analyst, detection diubah menjadi intermediate finding dengan threat object `rundll32.exe` beserta tujuan koneksinya, dan aksi otomatis yang tersisa hanya Nslookup dan Log an event. Pelajaran umumnya: setiap aksi otomatis yang mengubah sistem harus punya tiga hal yang tertulis sebelum diaktifkan, yaitu FP rate terukur, guardrail aset, dan batas jumlah.

Relay juga punya risiko sendiri. Heavy forwarder relay bisa menjalankan aksi ke jaringan internal atas perintah dari cloud, sehingga ia menjadi aset bernilai tinggi: batasi siapa yang bisa login ke HF itu, simpan API key seperti kredensial, dan pantau log eksekusinya [S3].

## 4. Contoh SPL dan langkah di ES

> Keluaran berlabel ilustrasi. Index hasil AR, perlu dicek.

### 4.1 Audit eksekusi AR

```
index=cim_modactions earliest=-7d
| stats count values(action_status) AS status BY action_name search_name user
| sort - count
```

- Field (`action_name`, `action_status`, `search_name`) adalah nama klasik, perlu dicek.
- **Cara membaca hasil:** aksi yang sering gagal (status error) menunjukkan masalah konfigurasi atau relay. Aksi containment yang banyak dijalankan oleh detection ber-FP tinggi adalah risiko.

### 4.2 Guardrail dalam SPL detection: hanya aset non-kritis untuk aksi otomatis

```
... detection logic ...
| lookup asset_lookup_by_str asset AS dest OUTPUTNEW priority AS dest_priority
| eval auto_contain=if(in(dest_priority,"critical","high"), "no", "yes")
```

- Gunakan field `auto_contain` sebagai syarat di SOAR atau pada dua detection terpisah (satu dengan aksi otomatis, satu tanpa), cek nama lookup aset (Day 26) dan cara memakai field sebagai kondisi aksi di ES 8.7.

### 4.3 Lab tanpa ES: alert action yang aman

- Alert action webhook ke Shuffle (lab) untuk enrichment (lookup reputasi domain uji), lalu membuat case di TheHive. Bukan tindakan containment.
- Alert action Run a script di lab hanya untuk skrip read-only (mis. `nslookup` dan menulis hasil ke file log). Simpan skrip di lokasi yang ditentukan dokumentasi, cek lokasi alert script di Splunk 10.

### 4.4 Matriks AR untuk satu detection (template)

```
Detection: Lab - Auth - Brute Force Followed By Success (Day 36)
Otomatis : Finding (high) | intermediate finding (user 40, src 20) | Nslookup src | Send email ke on-call (hanya jam kerja?)
Ad hoc   : Add Threat Intelligence (src) setelah verifikasi | Stream Capture bila src internal
SOAR     : playbook "Account Compromise" dengan persetujuan sebelum disable akun (Day 42)
Guardrail: tidak ada containment otomatis untuk user category=executive atau dest_priority=critical
Audit    : tinjau index hasil AR mingguan
```

### 4.5 Membaca hasil audit AR (keluaran ilustrasi)

Hasil query bagian 4.1 selama tujuh hari di lab fiktif:

```
action_name   search_name                                 user      count  status
nslookup      Lab - Auth - Brute Force Followed By Success  admin     84     success
notable       Lab - Auth - Brute Force Followed By Success  admin     84     success
ping          (ad hoc)                                      analyst1  3      success
script        Lab - Endpoint - Encoded PowerShell           admin     17     failure,success
email         Lab - Malware Detected                        admin     212    success
```

Cara membacanya:

- Nslookup dan notable berpasangan 84 kali: aksi otomatis berjalan setiap kali detection fire. Wajar.
- Ping ad hoc oleh `analyst1` tercatat dengan nama user-nya. Itu jejak akuntabilitas yang dicari auditor: siapa menjalankan apa.
- Script dengan status campuran `failure,success` perlu dibuka per event. Biasanya penyebabnya izin eksekusi, lokasi skrip, atau timeout ke tujuan.
- Email 212 kali dalam seminggu dari satu detection adalah tanda alert fatigue untuk penerimanya. Pertimbangkan throttling (Day 36) atau ubah ke ringkasan harian.

## 5. Lab praktik

1. Untuk 3 detection lab (Day 30, 36, 38), isi matriks bagian 4.4: otomatis / ad hoc / SOAR / guardrail.
2. **Dengan ES:** konfigurasikan Nslookup otomatis pada satu detection. Picu, lalu periksa hasilnya di finding dan bagian 4.1. Jalankan Ping secara ad hoc dari Mission Control.
3. **Tanpa ES:** buat alert dengan webhook ke Shuffle yang menambahkan observable ke case TheHive. Verifikasi alurnya.
4. Tulis satu paragraf: tindakan apa yang tidak akan kamu otomatiskan di organisasi fiktifmu, dan kenapa (gunakan bagian 3.2).

**Hasil yang sebaiknya tersimpan:**
- Matriks AR untuk 3 detection.
- Satu AR otomatis dan satu ad hoc berjalan (atau analog lab).
- Audit hasil aksi dilihat.
- Paragraf guardrail tertulis.

**Variasi tantangan:** rancang (di atas kertas) penerapan relay untuk skenario "ES di Splunk Cloud, firewall di data center on-prem": komponen, lokasi, API key, dan risiko keamanan relay itu sendiri [S3].

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Perbaikan |
|---|---|---|
| Aksi tidak muncul di daftar | App AR tidak terpasang/izin | Pasang app; cek capability |
| Aksi ad hoc gagal di Cloud | Relay belum dikonfigurasi atau API key tidak cocok | Ikuti langkah relay [S3] |
| Run a script tidak jalan | Skrip di lokasi salah; izin eksekusi | Simpan di lokasi yang didukung [S1] |
| Containment salah sasaran | Detection ber-FP tinggi diberi aksi otomatis | Turunkan ke ad hoc/SOAR dengan persetujuan; guardrail |
| Tidak ada jejak audit | Tidak memeriksa index hasil | bagian 4.1, cek index |

## 7. Kesalahan umum dan jebakan

- Mengotomatiskan containment dari detection yang belum teruji. Ukur FP dulu (Day 34).
- Menganggap AR = SOAR. AR adalah aksi tunggal; SOAR mengatur alur.
- Lupa audit trail. Tindakan otomatis harus bisa dipertanggungjawabkan.
- Add Threat Intelligence otomatis dari detection lemah. IOC salah akan menyebar ke threat match lain.
- Mengekspos jaringan internal demi AR dari cloud. Gunakan relay [S3].
- `[komunitas]` Matriks keputusan bagian 3.2 adalah sintesis dari prinsip umum (keyakinan, reversibilitas, blast radius), bukan aturan dari dokumentasi Splunk. Validasi terhadap kebijakan organisasi sebelum dipakai.

## 8. Catatan terkini

- **ES 8.7:** 13 AR bawaan, termasuk Finding. Eksekusi otomatis lewat detection editor, ad hoc lewat Mission Control [S1].
- Relay dari Splunk Cloud ke on-prem tetap didukung di ES 8.x [S3].
- Release notes ES 8.7 menyebut AI SOC Analyst yang dapat menjalankan tindakan yang diizinkan dan merekomendasikan langkah ketika persetujuan analyst dibutuhkan. Batas izinnya perlu dicek di instance. Guardrail dan audit menjadi lebih penting.

## 9. Cheat sheet

```
AR = aksi dari detection (otomatis) atau dari finding (ad hoc, Mission Control)
BAWAAN 8.7: Finding | Send email | Log an event | Stream Capture | Nbtstat | Nslookup | Ping | Run a script
            | Create Splunk messages | Add Threat Intelligence | Send to UBA | Send to Splunk Mobile | Output to telemetry endpoint
OTOMATIS: enrichment, artefak kerja, notifikasi terbatas ; AD HOC/SOAR: tindakan berdampak
KEPUTUSAN: confidence x reversibilitas x blast radius x kebijakan ; guardrail dari A&I (priority, category)
RELAY (Cloud->on-prem): HF + AR add-on + modular action relay (HF) + modular action worker (cloud SH) + API key ; pilih worker set
KUSTOM: alert action sesuai common action model (CIM); Add-on Builder, perlu dicek
AUDIT: index hasil AR (klasik: cim_modactions), perlu dicek
AR vs SOAR: aksi tunggal vs alur multi-langkah + persetujuan
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | ES 8.7: Configure adaptive response actions for detections (lihat Day 31) | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/detections/configure-adaptive-response-actions-for-detections-in-splunk-enterprise-security | primer | diakses 2026-10-07 | Tinggi |
| S2 | ES 6.1: Configure adaptive response actions for a correlation search (konteks ES lama) | https://docs.splunk.com/Documentation/ES/6.1.1/Admin/Configureadaptiveresponse | primer | lama (>3 tahun) | Sedang; konteks historis |
| S3 | ES 8.4: Configure adaptive response action relays | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.4/detections/configure-adaptive-response-action-relays-in-splunk-enterprise-security | primer | diakses 2026-10-07 | Tinggi |
| S4 | Overview of the Splunk CIM (common action model; lihat Day 23) | https://help.splunk.com/en/data-management/common-information-model | primer | diakses 2026-10-07 | Tinggi |
| S5 | ES 8.7: Asset and identity (guardrail konteks; lihat Day 26) | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/asset-and-identity-management | primer | diakses 2026-10-07 | Tinggi |

**Catatan sumber:** index hasil AR di ES 8.7 (klasik `cim_modactions`), dukungan AR di Add-on Builder terkini, daftar aksi yang didukung relay, dan pemakaian field sebagai kondisi aksi di ES 8.7 perlu dicek di instance. Studi kasus di bagian 3.6 dan keluaran di bagian 4.5 fiktif.
