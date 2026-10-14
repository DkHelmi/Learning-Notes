---
day: 41
title: 'Adaptive response action: kapan dipakai dan cara mengonfigurasinya'
researched_on: 2026-10-10
versions_checked: Splunk ES 8.7 (Configure adaptive response actions for detections); ES 8.4 (Adaptive response action relays); Splunk CIM 6.x (common action model); Splunk Enterprise 10.6
---

# Day 41: Adaptive response action, kapan dan bagaimana

Cakupan: menentukan kapan memakai adaptive response action dan mengonfigurasinya sesuai kebutuhan.

## Ide inti

Bagian sebelumnya berhenti pada saat sebuah finding lahir: detection menyala, risiko terakumulasi, dan satu item muncul di antrean analyst. Adaptive response (AR) adalah langkah sesudahnya, yaitu aksi yang dijalankan ES atas sebuah detection ketika ia menyala, atau dijalankan analyst atas sebuah finding yang sudah ada di depannya. Aksinya bisa membuat artefak kerja, mengambil konteks tambahan, memberi tahu orang, atau mengubah sesuatu di luar Splunk. Dokumentasi ES menempatkan nilainya pada pengumpulan informasi dan dimulainya tindakan sebelum investigasi berjalan, sehingga triage lebih cepat [S1][S2]. Daftar AR bawaan sudah lewat sebagai istilah di Day 31; yang dikerjakan Day ini adalah keputusan memakainya.

Keputusan itulah bagian yang sulit, bukan konfigurasinya. Mengisi parameter sebuah aksi di detection editor selesai dalam semenit. Menentukan aksi mana yang boleh berjalan tanpa manusia di depannya adalah pekerjaan lain, karena tindakan otomatis mempercepat respons sekaligus memperbesar akibat dari satu detection yang keliru. Memblokir server produksi karena false positive bisa lebih merugikan daripada serangan yang sedang dicegah. Seluruh Day ini berdiri di atas satu kebiasaan yang keluar dari kenyataan itu: otomatiskan pengambilan konteks secara luas, dan tindakan yang mengubah sistem secara sempit.

Padanannya sudah kamu kenal dari konsol NOC, yaitu tombol aksi yang menempel di layar yang sedang kamu baca: men-shutdown satu interface, memblokir sebuah IP di perimeter, mengisolasi perangkat dari jaringan. Di SOC bentuknya sama, ditambah aksi khas keamanan seperti mengirim sampel ke sandbox. Batas analoginya ada pada siapa yang menekan. Tombol di konsol selalu punya manusia di belakangnya, sedangkan AR bisa berjalan sendiri atas perintah sebuah detection, jadi persetujuan dan jejak audit yang di NOC muncul dengan sendirinya harus dirancang sebagai bagian dari konfigurasi di sini.

Di PT Jaringan Anak Bangsa (PT JAB, ISP menengah fiktif), ES baru dipasang di search head terpisah sementara sebagian alert L1 masih berjalan dari app Search & Reporting, jadi dua bentuk aksi hidup berdampingan: AR di sisi ES, dan alert action biasa di sisi Search & Reporting.

**Kapan relevan:** saat memutuskan aksi apa yang pantas menempel di sebuah detection dan aksi apa yang disisakan untuk analyst; saat L1 sebaiknya sudah menemukan konteks dasar di finding sebelum ia mulai menggali; saat auditor meminta bukti siapa menjalankan tindakan apa dan kapan; dan saat ES berada di Splunk Cloud sementara perangkat yang harus disentuh ada di jaringan on-prem.
**Kapan bukan jawaban:** AR tidak memperbaiki detection yang false positive-nya belum pernah diukur, dan memberinya aksi otomatis hanya melipatgandakan kesalahannya (Day 36). AR juga bukan tempat untuk alur bercabang yang melibatkan beberapa alat dan persetujuan di tengah jalan, karena itu pekerjaan SOAR playbook (Day 42). Containment yang sebenarnya, misalnya isolasi host di EDR atau blokir di firewall, umumnya datang dari AR app vendor atau dari playbook, bukan dari aksi bawaan. Dan aksi apa pun tidak menggantikan disposisi: yang memutuskan sebuah finding true positive atau bukan tetap analyst.

## 1. Konsep inti

### 1.1 Jenis AR berdasarkan tujuan

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

### 1.2 Kapan otomatis, kapan ad hoc: matriks keputusan

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

### 1.3 Mengonfigurasi AR

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

### 1.4 AR vs SOAR

| | Adaptive response | SOAR playbook |
|---|---|---|
| Lingkup | Satu aksi per eksekusi (atau beberapa aksi terpisah) | Alur multi-langkah dengan logika, percabangan, persetujuan |
| Tempat | Di ES (detection/finding) | Di platform SOAR, dipicu dari ES |
| Cocok untuk | Enrichment cepat, notifikasi, aksi sederhana | Respons kompleks, integrasi banyak alat, human-in-the-loop |

Detail SOAR di Day 42.

### 1.5 Studi kasus fiktif: isolasi otomatis yang salah sasaran

Sebuah SOC memasang aksi isolasi host (dari app AR vendor EDR) secara otomatis pada detection "Suspicious Rundll32 Network Connection". Detection itu baru dua minggu aktif dan FP rate-nya belum pernah diukur. Pada Senin pagi, update agen backup memakai `rundll32.exe` untuk memanggil komponen yang menghubungi server backup. Dalam 20 menit, 46 host diisolasi, termasuk dua server aplikasi kasir.

Apa yang salah, dilihat dari matriks bagian 1.2:

- **Keyakinan:** rendah, karena belum ada data disposition (Day 34). Detection seperti ini seharusnya hanya mendapat enrichment atau output risk.
- **Reversibilitas:** isolasi bisa dibatalkan, tetapi tidak cepat untuk 46 host, dan butuh orang yang punya akses konsol EDR.
- **Blast radius:** tidak ada guardrail berbasis prioritas aset, sehingga server kritis ikut terkena.
- **Batas jumlah:** tidak ada pembatas "maksimal N aksi per jam". Pembatas sederhana akan menghentikan kejadian setelah host ketiga.

Perbaikan yang diambil: aksi isolasi dipindah ke SOAR dengan persetujuan analyst, detection diubah menjadi intermediate finding dengan threat object `rundll32.exe` beserta tujuan koneksinya, dan aksi otomatis yang tersisa hanya Nslookup dan Log an event. Pelajaran umumnya: setiap aksi otomatis yang mengubah sistem harus punya tiga hal yang tertulis sebelum diaktifkan, yaitu FP rate terukur, guardrail aset, dan batas jumlah.

Relay juga punya risiko sendiri. Heavy forwarder relay bisa menjalankan aksi ke jaringan internal atas perintah dari cloud, sehingga ia menjadi aset bernilai tinggi: batasi siapa yang bisa login ke HF itu, simpan API key seperti kredensial, dan pantau log eksekusinya [S3].

**Tanpa ES:** di Splunk Enterprise biasa padanannya adalah alert action, yaitu email, webhook, skrip, dan alert action yang dibawa app, dan pembedaan antara aksi otomatis dan aksi manual berlaku sama di sana. Yang ditambahkan ES adalah integrasi AR dengan finding, eksekusi ad hoc dari Mission Control, relay untuk menjalankan aksi dari cloud ke on-prem, dan pencatatan hasil setiap eksekusi. Di PT JAB, L1 yang masih bekerja di app Search & Reporting memakai alert action untuk hal yang sama, dan latihannya ada di bagian 2.3.

## 2. Contoh SPL dan langkah di ES

> Keluaran berlabel ilustrasi. Index hasil AR, perlu dicek.

### 2.1 Audit eksekusi AR

```
index=cim_modactions earliest=-7d
| stats count values(action_status) AS status BY action_name search_name user
| sort - count
```

- Field (`action_name`, `action_status`, `search_name`) adalah nama klasik, perlu dicek.
- **Cara membaca hasil:** aksi yang sering gagal (status error) menunjukkan masalah konfigurasi atau relay. Aksi containment yang banyak dijalankan oleh detection ber-FP tinggi adalah risiko.

### 2.2 Guardrail dalam SPL detection: hanya aset non-kritis untuk aksi otomatis

```
... detection logic ...
| lookup asset_lookup_by_str asset AS dest OUTPUTNEW priority AS dest_priority
| eval auto_contain=if(in(dest_priority,"critical","high"), "no", "yes")
```

- Gunakan field `auto_contain` sebagai syarat di SOAR atau pada dua detection terpisah (satu dengan aksi otomatis, satu tanpa), cek nama lookup aset (Day 26) dan cara memakai field sebagai kondisi aksi di ES 8.7.

### 2.3 Lab tanpa ES: alert action yang aman

- Alert action webhook ke Shuffle (lab) untuk enrichment (lookup reputasi domain uji), lalu membuat case di TheHive. Bukan tindakan containment.
- Alert action Run a script di lab hanya untuk skrip read-only (mis. `nslookup` dan menulis hasil ke file log). Simpan skrip di lokasi yang ditentukan dokumentasi, cek lokasi alert script di Splunk 10.

### 2.4 Matriks AR untuk satu detection (template)

```
Detection: Lab - Auth - Brute Force Followed By Success (Day 36)
Otomatis : Finding (high) | intermediate finding (user 40, src 20) | Nslookup src | Send email ke on-call (hanya jam kerja?)
Ad hoc   : Add Threat Intelligence (src) setelah verifikasi | Stream Capture bila src internal
SOAR     : playbook "Account Compromise" dengan persetujuan sebelum disable akun (Day 42)
Guardrail: tidak ada containment otomatis untuk user category=executive atau dest_priority=critical
Audit    : tinjau index hasil AR mingguan
```

### 2.5 Membaca hasil audit AR (keluaran ilustrasi)

Hasil query bagian 2.1 selama tujuh hari di lab fiktif:

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

## 3. Lab praktik

1. Untuk 3 detection lab (Day 30, 36, 38), isi matriks bagian 2.4: otomatis / ad hoc / SOAR / guardrail.
2. **Dengan ES:** konfigurasikan Nslookup otomatis pada satu detection. Picu, lalu periksa hasilnya di finding dan bagian 2.1. Jalankan Ping secara ad hoc dari Mission Control.
3. **Tanpa ES:** buat alert dengan webhook ke Shuffle yang menambahkan observable ke case TheHive. Verifikasi alurnya.
4. Tulis satu paragraf: tindakan apa yang tidak akan kamu otomatiskan di organisasi fiktifmu, dan kenapa (gunakan bagian 1.2).

**Hasil yang sebaiknya tersimpan:**
- Matriks AR untuk 3 detection.
- Satu AR otomatis dan satu ad hoc berjalan (atau analog lab).
- Audit hasil aksi dilihat.
- Paragraf guardrail tertulis.

**Variasi tantangan:** rancang (di atas kertas) penerapan relay untuk skenario "ES di Splunk Cloud, firewall di data center on-prem": komponen, lokasi, API key, dan risiko keamanan relay itu sendiri [S3].

## 4. Troubleshooting

| Gejala | Kemungkinan penyebab | Perbaikan |
|---|---|---|
| Aksi tidak muncul di daftar | App AR tidak terpasang/izin | Pasang app; cek capability |
| Aksi ad hoc gagal di Cloud | Relay belum dikonfigurasi atau API key tidak cocok | Ikuti langkah relay [S3] |
| Run a script tidak jalan | Skrip di lokasi salah; izin eksekusi | Simpan di lokasi yang didukung [S1] |
| Containment salah sasaran | Detection ber-FP tinggi diberi aksi otomatis | Turunkan ke ad hoc/SOAR dengan persetujuan; guardrail |
| Tidak ada jejak audit | Tidak memeriksa index hasil | bagian 2.1, cek index |

## 5. Kesalahan umum dan jebakan

- Mengotomatiskan containment dari detection yang belum teruji. Ukur FP dulu (Day 34).
- Menganggap AR = SOAR. AR adalah aksi tunggal; SOAR mengatur alur.
- Lupa audit trail. Tindakan otomatis harus bisa dipertanggungjawabkan.
- Add Threat Intelligence otomatis dari detection lemah. IOC salah akan menyebar ke threat match lain.
- Mengekspos jaringan internal demi AR dari cloud. Gunakan relay [S3].
- `[komunitas]` Matriks keputusan bagian 1.2 adalah sintesis dari prinsip umum (keyakinan, reversibilitas, blast radius), bukan aturan dari dokumentasi Splunk. Validasi terhadap kebijakan organisasi sebelum dipakai.

## 6. Catatan terkini

- **ES 8.7:** 13 AR bawaan, termasuk Finding. Eksekusi otomatis lewat detection editor, ad hoc lewat Mission Control [S1].
- Relay dari Splunk Cloud ke on-prem tetap didukung di ES 8.x [S3].
- Release notes ES 8.7 menyebut AI SOC Analyst yang dapat menjalankan tindakan yang diizinkan dan merekomendasikan langkah ketika persetujuan analyst dibutuhkan. Batas izinnya perlu dicek di instance. Guardrail dan audit menjadi lebih penting.

## 7. Cheat sheet

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

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Rekanmu mengaktifkan aksi isolasi host secara otomatis pada sebuah detection yang baru dua minggu hidup, dengan alasan "aksinya sudah disediakan ES, jadi aman dipakai". Ada dua kekeliruan di satu kalimat itu. Sebutkan keduanya.

<details><summary>Jawaban</summary>

Pertama, isolasi host bukan aksi bawaan ES. Containment yang benar-benar mengubah sistem, seperti isolasi host di EDR, menonaktifkan akun, atau memblokir di firewall, biasanya datang dari AR app vendor di Splunkbase atau dari SOAR playbook, sehingga yang dipasang rekanmu adalah aksi milik produk lain beserta hak dan risikonya sendiri. Kedua, ketersediaan sebuah aksi tidak mengatakan apa pun tentang kelayakan menjalankannya otomatis. Yang menentukan itu keyakinan terhadap detection-nya, dan detection berumur dua minggu yang FP rate-nya belum pernah diukur masuk kategori keyakinan rendah, yang pantasnya hanya mendapat enrichment atau output risk. Lihat bagian 1.1, 1.2, dan 1.5.

</details>

**2. Skenario keputusan.** ES PT JAB berada di Splunk Cloud, sedangkan firewall yang perlu disentuh sebuah aksi ada di data center on-prem. Mana langkah yang tepat?

- A. Buka akses dari search head cloud ke jaringan internal supaya aksinya bisa menjangkau firewall.
- B. Pasang relay: heavy forwarder on-prem dengan add-on Adaptive Response, modular action relay di HF, modular action worker di search head cloud, dan API key yang cocok di kedua sisi, lalu pilih worker set saat membuat detection.
- C. Pindahkan semua aksi ke SOAR, karena masalah seperti ini tidak ada di platform SOAR.

<details><summary>Jawaban</summary>

B. Itu memang mekanisme yang disediakan untuk kasus ini: aksi diantrekan di search head cloud, lalu relay on-prem mengambil dan menjalankannya, sehingga tidak ada jalur masuk baru ke jaringan internal. A adalah hal yang justru dihindari desain relay, karena membuka akses dari luar ke dalam demi satu aksi menukar risiko yang jauh lebih besar dengan kenyamanan. C mencampurkan dua hal: SOAR menangani alur multi-langkah, bukan satu aksi tunggal, dan memindahkan alat tidak menghapus pertanyaan konektivitas, karena SOAR pun tetap perlu jalur yang dirancang ke perangkat on-prem. Perlu diingat bahwa relay sendiri menjadi aset bernilai tinggi: ia menjalankan perintah dari cloud ke jaringan internal, jadi akses login ke HF itu dibatasi, API key diperlakukan sebagai kredensial, dan log eksekusinya dipantau. Lihat bagian 1.3 dan 1.5.

</details>

**3. Pertanyaan jebakan.** Auditor internal meminta bukti siapa menjalankan aksi apa pekan lalu. Rekanmu menjawab bahwa bukti itu tidak ada karena aksi dijalankan oleh ES, bukan oleh orang. Kenapa jawaban itu salah, dan apa yang kamu cek lebih dulu?

<details><summary>Jawaban</summary>

Setiap eksekusi AR tercatat, termasuk hasilnya. Secara klasik ES menyimpan hasil aksi di index `cim_modactions` dengan field seperti `action_name`, `action_status`, `search_name`, dan `user`, jadi aksi ad hoc muncul dengan nama user yang menekannya dan aksi otomatis muncul dengan nama detection yang memicunya. Yang dicek lebih dulu adalah nama index dan nama field itu di ES 8.7, karena keduanya nama klasik dan perlu dikonfirmasi di instance sendiri sebelum dipakai sebagai bukti. Hasil audit yang sama sekalian memperlihatkan dua hal lain: aksi yang sering berstatus error menunjukkan masalah konfigurasi atau relay, dan satu detection yang mengirim ratusan email per minggu adalah tanda alert fatigue. Lihat bagian 1.3, 2.1, dan 2.5.

</details>

**4. Jelaskan ulang.** Jelaskan ke SOC lead, dalam tiga kalimat, kenapa enrichment boleh diotomatiskan secara luas sementara tindakan yang mengubah sistem dipasang secara sempit.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh jawaban: "Enrichment bersifat read-only, jadi biaya kesalahannya hampir nol dan manfaatnya langsung terasa karena analyst sudah menemukan konteks dasar di finding sebelum ia mulai menggali. Tindakan yang mengubah sistem punya biaya kesalahan yang nyata, dan besarnya ditentukan empat hal yang kami timbang satu per satu: keyakinan terhadap detection-nya, apakah tindakan itu bisa dibatalkan dengan cepat, seberapa luas dampaknya bila salah sasaran, dan apakah kebijakan menuntut persetujuan lebih dulu. Karena itu tindakan otomatis hanya kami pasang untuk detection yang FP rate-nya sudah terukur, dengan guardrail dari konteks aset dan identitas serta batas jumlah aksi per jam, dan sisanya dijalankan ad hoc oleh analyst atau lewat playbook dengan persetujuan."

Kesalahan yang sering muncul: menyebut otomasi sebagai hal yang baik atau buruk secara umum, padahal keputusannya per aksi dan per detection; lupa bahwa guardrail butuh data aset dan identitas yang lengkap, sehingga aset yang tidak terdaftar justru lolos dari pembatas; dan memasang aksi otomatis tanpa batas jumlah, yang membuat satu false positive berubah menjadi puluhan tindakan sebelum ada yang menyadarinya. Lihat bagian 1.2 dan 1.5.

</details>

**5. Interview question (English).** "When would you let your SIEM take an action automatically, and when do you insist on a human in the loop?"

<details><summary>Sample answer</summary>

"I split actions by what they do to the world. Anything read-only, so enrichment like a DNS lookup, asset and identity context, or a reputation check, I automate broadly, because it costs nothing if the alert turns out to be false and it means the analyst opens a finding that already has context attached. Anything that changes a system, such as isolating a host, disabling an account or pushing a firewall block, I weigh on four things: how confident the detection is, measured from its actual false positive rate rather than my impression of it; whether the action can be reversed quickly and by whom; how wide the blast radius is if it fires on the wrong target; and whether policy or legal requires approval first, which it usually does for executives and for anything customer facing. In practice that means high confidence plus low impact and reversible gets automated, high impact gets automated only with guardrails such as excluding critical assets and capping the number of actions per hour, and everything else is run ad hoc by an analyst or through a playbook with an approval step. I also treat the audit trail as part of the design, not an afterthought, because every execution needs to answer who ran what, when, and with what result, and in a cloud deployment I use a relay rather than opening inbound access to the internal network. The failure I have seen most often is an untested detection wired to a containment action, where one benign software update isolates dozens of machines in twenty minutes, and it is entirely preventable with a measured false positive rate, an asset guardrail, and a rate limit."

What makes this answer strong: it separates read-only from state-changing actions instead of arguing about automation in general, names the four factors it actually weighs, ties the decision to a measured false positive rate rather than intuition, and treats auditability and the cloud-to-on-prem path as part of the design.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | ES 8.7: Configure adaptive response actions for detections (lihat Day 31) | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/detections/configure-adaptive-response-actions-for-detections-in-splunk-enterprise-security | primer | diakses 2026-10-07 | Tinggi |
| S2 | ES 6.1: Configure adaptive response actions for a correlation search (konteks ES lama) | https://docs.splunk.com/Documentation/ES/6.1.1/Admin/Configureadaptiveresponse | primer | lama (>3 tahun) | Sedang; konteks historis |
| S3 | ES 8.4: Configure adaptive response action relays | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.4/detections/configure-adaptive-response-action-relays-in-splunk-enterprise-security | primer | diakses 2026-10-07 | Tinggi |
| S4 | Overview of the Splunk CIM (common action model; lihat Day 23) | https://help.splunk.com/en/data-management/common-information-model | primer | diakses 2026-10-07 | Tinggi |
| S5 | ES 8.7: Asset and identity (guardrail konteks; lihat Day 26) | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/asset-and-identity-management | primer | diakses 2026-10-07 | Tinggi |

**Catatan sumber:** index hasil AR di ES 8.7 (klasik `cim_modactions`), dukungan AR di Add-on Builder terkini, daftar aksi yang didukung relay, dan pemakaian field sebagai kondisi aksi di ES 8.7 perlu dicek di instance. Studi kasus di bagian 1.5 dan keluaran di bagian 2.5 fiktif.
