---
day: 33
title: 'Mission Control: dari finding ke investigation, response plan, disposition, dan threat intelligence di ES 8'
researched_on: 2026-10-09
versions_checked: 'Splunk Enterprise Security 8.7 (Mission Control user guide; Create response plans; Included response plans; Threat intelligence administer guide 8.7); rujukan Day 18, 19, 20, 22, 23, 26, 27'
---

# Day 33: Mission Control, investigation, dan threat intelligence di ES 8

Cakupan: alur kerja analyst di Mission Control dari finding sampai penutupan, investigation sebagai wadah bukti, response plan berisi phase dan task, pemberian disposition, serta dua jalur threat intelligence di ES 8 yang sering tertukar.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- menjelaskan perjalanan satu finding dari analyst queue sampai investigation tertutup, beserta keputusan di tiap langkah.
- membedakan finding, finding group, dan investigation, dan menyebut apa yang dibawa masing-masing.
- membuat dan menerapkan response plan berisi phase dan task, termasuk task yang memuat search atau playbook.
- memberi disposition yang tepat dan menjelaskan kenapa disposition adalah data, bukan formalitas.
- membedakan native threat intelligence dari Threat Intelligence Management (Cloud) di ES 8, dan tahu di mana indikatormu akan muncul.
- menulis note investigasi yang masih berguna enam bulan kemudian.

## 2. Konteks singkat

Day 18 memberi kerangka lima tahap investigasi, Day 19 memberi metrik dan disposition, Day 22 dan Day 23 memberi cara finding lahir. Day ini menyambungkan semuanya di tempat pekerjaan itu benar-benar terjadi: Mission Control, antarmuka tempat analyst ES 8 bekerja sehari-hari.

Dokumentasi Splunk menempatkan Mission Control sebagai tempat analyst melakukan triage, investigasi, dan respons terhadap insiden, lengkap dengan timeline untuk melihat kapan finding terjadi [S1]. Finding dan finding group yang muncul di analyst queue dihasilkan oleh detection, baik dari raw event maupun dari alert pihak ketiga [S1].

Yang membuat Day ini layak dipelajari serius: sebagian besar nilai sebuah SOC tidak hilang di tahap deteksi, melainkan di tahap pencatatan. Investigasi yang benar tetapi tidak terdokumentasi menghasilkan metrik yang salah, tuning yang tidak pernah terjadi, dan pengetahuan yang hilang saat orangnya pindah kerja.

**Kapan dipakai:** setiap shift triage; saat menyusun prosedur SOC; saat menilai kualitas kerja tim; saat menyiapkan bahan interview, karena pertanyaan "ceritakan satu investigasi yang kamu kerjakan" dijawab dari catatan seperti ini.

## 3. Konsep inti

### 3.1 Finding, finding group, dan investigation

| Objek | Apa itu | Dibuat oleh |
|---|---|---|
| Finding | Satu hasil detection yang perlu dilihat analyst (istilah ES 7: notable event) | Event-based detection (Day 23) |
| Intermediate finding | Jejak risiko yang dikumpulkan, bukan untuk ditriage satu per satu (istilah ES 7: risk event) | Risk rule atau detection dengan output risiko (Day 22) |
| Finding group | Kumpulan finding dan intermediate finding yang terkait pada satu entity, hasil finding-based detection | Finding-based detection (Day 22) |
| Investigation | Wadah terstruktur untuk mengumpulkan bukti dan menjalankan respons [S1] | Analyst, dari satu atau beberapa finding |

Perbedaan penting dalam praktik: finding adalah pemicu, investigation adalah pekerjaan. Satu investigation bisa menampung banyak finding, dan justru itu gunanya. Membuat satu investigation per finding untuk insiden yang sama menghasilkan metrik yang menyesatkan dan pekerjaan ganda.

### 3.2 Alur kerja yang dianjurkan

Dokumentasi ES 8.7 menyusun alurnya seperti ini [S1]:

1. Ambil finding (assign ke diri sendiri), ubah statusnya, simpan.
2. Mulai investigation, lalu tinjau event, field, note, dan file di dalamnya.
3. Tambahkan response plan supaya langkahnya standar untuk jenis insiden itu.
4. Jalankan action dan playbook untuk mengumpulkan informasi tambahan.
5. Pakai sumber threat intelligence untuk memperbarui investigation dan menilai risiko observable.
6. Jaga investigation tetap mutakhir supaya analyst lain bisa mengikuti perkembangannya.
7. Beri disposition, lalu tutup investigation ketika insiden selesai.

Yang perlu ditambahkan dari sisi praktik, karena dokumentasi tidak menuliskannya:

- **Assign sebelum bekerja, bukan sesudah.** Dua analyst yang mengerjakan finding yang sama adalah pemborosan paling umum di shift yang sibuk.
- **Tulis hipotesis di note sejak awal.** Satu kalimat: "dugaan awal: brute force berhasil dari IP luar ke akun svc_backup". Hipotesis yang tertulis membuat bias lebih mudah dikoreksi.
- **Catat yang tidak kamu temukan.** "Tidak ada proses anak mencurigakan dalam 2 jam setelah login" adalah temuan, bukan kekosongan.
- **Cantumkan cakupan data.** Rentang waktu, index, dan keterbatasan (Day 31 bagian 3.7). Ini yang membedakan laporan yang bisa dipertahankan dari laporan yang hanya terdengar meyakinkan.

### 3.3 Investigation sebagai wadah bukti

Isi sebuah investigation yang sehat:

- **Events:** finding dan event pendukung yang kamu tambahkan dari hasil search.
- **Fields:** entity yang terlibat (user, host, IP) yang menjadi poros pivot.
- **Notes:** catatan analisis bertanggal, termasuk query yang kamu jalankan.
- **Files:** lampiran seperti hasil ekspor, screenshot dashboard, atau laporan triage.
- **Timeline:** urutan kejadian, bukan urutan pekerjaanmu.

Bedakan dua jenis waktu ini secara sadar. Timeline insiden berisi kapan penyerang melakukan sesuatu. Riwayat pekerjaan berisi kapan kamu melakukan sesuatu. Keduanya perlu, tetapi mencampurnya membuat laporan sulit dibaca dan membuat perhitungan dwell time salah (Day 19).

Satu kebiasaan yang membuat note jauh lebih berguna: tulis query lengkap beserta rentang waktunya di dalam note, bukan hanya kesimpulannya. Enam bulan kemudian, query itu yang membuat temuanmu bisa diulang.

### 3.4 Response plan: phase dan task

Response plan adalah template berisi phase dan task yang diikuti analyst supaya investigasi untuk jenis insiden yang sama mendapat penanganan standar [S2]. ES 8 menyertakan beberapa plan bawaan, antara lain NIST 800-61 (fase dan task berdasar panduan penanganan insiden NIST) dan Generic Incident Response (fase dari deteksi sampai review) [S3].

Yang perlu diketahui saat membuat plan sendiri [S2]:

- Plan dibangun dari phase, dan setiap phase berisi task.
- Deskripsi task mendukung Markdown, jadi langkah bisa ditulis rapi dengan daftar dan blok kode.
- Satu task bisa dilampiri action atau playbook (Day 26 dan Day 27), sehingga analyst tidak perlu berpindah antarmuka.
- Satu task bisa memuat search yang bisa dijalankan langsung dari task itu. Saat dijalankan dari tab Response, search bawaan task berjalan untuk 24 jam terakhir secara default [S4].
- Plan hanya bisa dipasang ke investigation setelah statusnya Published.
- Plan bisa diimpor dari file JSON, dan JSON adalah satu-satunya format yang didukung.
- Plan bisa dipasang ke satu investigation saat bekerja, atau diikat ke sebuah investigation type supaya setiap investigation baru dengan jenis itu otomatis memakainya [S4].

Cara memakai fitur ini dengan baik: jangan menyalin prosedur panjang apa adanya. Satu task yang baik berbunyi seperti perintah yang bisa dijalankan dan diverifikasi ("jalankan search X untuk rentang Y, catat jumlah host terdampak"), bukan seperti kebijakan ("pastikan dampak dinilai dengan tepat").

### 3.5 Disposition dan penutupan

Saat menutup, analyst memberi disposition. Pilihan intinya di ES 8 mencakup true positive, benign positive, false positive, dan undetermined, dengan rincian seperti false positive karena logika analitik yang salah atau karena data tidak akurat (Day 19 bagian 3.3) [S4].

Kenapa ini bukan formalitas:

- Disposition adalah sumber data untuk mengukur kualitas detection. Tanpa itu, tidak ada cara objektif menentukan detection mana yang perlu di-tuning (Day 19).
- Benign positive memberi informasi berbeda dari false positive. Benign positive berarti deteksimu benar dan aktivitasnya nyata, tetapi diizinkan. Perbaikannya ada di allowlist yang terkelola (Day 32 bagian 3.5), bukan di logika.
- False positive karena data tidak akurat mengarahkan perbaikan ke onboarding (Day 30), bukan ke search.

Aturan yang membuat metrik tetap bersih: disposition diberikan oleh orang yang mengerjakan, pada hari yang sama, dan selalu disertai satu baris alasan di note.

### 3.6 Dua jalur threat intelligence di ES 8

Ini bagian yang paling sering membuat bingung, dan perlu dibaca dengan teliti karena berbeda antara deployment.

**Jalur native (threat intelligence framework klasik).** Modular input `threatlist` mengunduh atau membaca file yang diunggah, memparsenya, lalu menambahkan indikator ke koleksi KV store ES [S5]. Dari sana, threat matching search mencocokkan indikator dengan event dan menghasilkan finding. Format yang didukung mencakup berbagai jenis daftar indikator serta STIX dan OpenIOC [S6]. Jalur ini yang dipakai sebagian besar deployment self-managed.

**Jalur Threat Intelligence Management (Cloud), disingkat TIM.** Di ES 8.7, halaman konfigurasi threat list menyatakan dirinya berlaku hanya untuk pengguna TIM (Cloud), bukan untuk native threat intelligence [S5]. Di jalur ini kamu bisa membuat sampai lima threat list dari indikator yang dipublikasikan sumber data TIM, untuk dipakai di threat matching dan pengayaan investigasi. Setiap threat list punya tiga bagian yang bisa disesuaikan: detail, sumber intelijen, dan tipe daftar (misalnya indicator prioritization) [S5].

Konsekuensi praktis yang wajib kamu ingat: halaman Intelligence di dalam sebuah investigation menampilkan data dari TIM (Cloud) saja, bukan dari koleksi KV store native [S5]. Jadi bila di lab kamu memakai jalur native lalu membuka tab Intelligence dan melihatnya kosong, itu bukan kesalahan konfigurasi indikator, melainkan perbedaan jalur.

Istilah pendamping: observable adalah data yang menandakan sebuah event teramati di sistem, jaringan, atau entitas digital lain [S5]. Di ES 7 istilah yang dipakai adalah threat object atau indicator (Day 20).

### 3.7 Menulis note yang masih berguna nanti

Kerangka note yang terbukti praktis, cukup lima baris:

```
[2026-10-09 14:22] Hipotesis: brute force berhasil ke svc_backup dari 203.0.113.50 (finding FG-128).
[2026-10-09 14:35] Dicek: index=lab_auth earliest=-24h@h user=svc_backup -> 412 gagal, 1 sukses 13:58 dari 203.0.113.50.
[2026-10-09 14:50] Dicek: Endpoint.Processes dest=LAB-SRV-01 setelah 13:58 -> tidak ada proses anak di luar baseline (first-seen bersih, Day 32).
[2026-10-09 15:05] Penilaian: kredensial kemungkinan bocor (keyakinan sedang); belum ada tanda eksekusi. Keterbatasan: EDR tidak terpasang di SRV-01.
[2026-10-09 15:10] Tindakan: reset kredensial (tiket LAB-114), blokir IP di edge, tambah hunt harian untuk akun service.
```

Empat unsur yang harus selalu ada: hipotesis, bukti beserta query dan rentangnya, penilaian dengan tingkat keyakinan, dan keterbatasan. Unsur kelima yang membedakan analyst senior: tindakan lanjutan yang spesifik dan punya pemilik.

## 4. Contoh dan langkah di ES

> Keluaran berlabel ilustrasi. ES dideskripsikan generik; nama menu dicocokkan ke dokumentasi ES 8.7 dan perlu dicek bila versimu berbeda.

### 4.1 Triage satu finding, langkah demi langkah

1. Buka Mission Control, urutkan analyst queue berdasarkan urgency, lalu pilih satu finding.
2. Assign ke dirimu dan ubah status menjadi in progress. Ini mencegah pekerjaan ganda [S1].
3. Baca finding-nya sendiri dulu: detection apa yang memicunya, entity apa yang terlibat, annotation ATT&CK apa yang terbawa (Day 16).
4. Buat investigation dari finding itu, atau tambahkan ke investigation yang sudah ada bila insidennya sama.
5. Tulis note hipotesis (bagian 3.7) sebelum menjalankan search apa pun.
6. Tambahkan response plan yang sesuai jenis insiden lewat tab Response [S4].
7. Kerjakan task satu per satu. Jalankan search bawaan task dan sesuaikan rentang waktunya, karena default-nya 24 jam terakhir [S4].
8. Tambahkan event pendukung dan field entity ke investigation supaya timeline terbentuk.
9. Jalankan action atau playbook bila diperlukan, misalnya lookup reputasi atau pengumpulan artefak (Day 26 dan Day 27).
10. Tulis note penilaian, beri disposition, lalu tutup.

### 4.2 Search pendamping untuk melihat beban dan hasil triage

Finding di ES tetap bisa dianalisis dengan SPL. Nama index dan macro bisa berbeda antar versi, jadi mulai dengan memastikan mana yang tersedia di instance-mu:

```
| rest /services/data/indexes | search title IN ("notable","risk","finding*") | table title currentDBSizeMB totalEventCount
```

Bila index notable tersedia, distribusi disposition per detection bisa dilihat seperti ini:

```
index=notable earliest=-30d
| stats count BY search_name disposition
| eventstats sum(count) AS total BY search_name
| eval persen=round(count/total*100,1)
| where disposition IN ("false positive","FP - Incorrect Analytic Logic","FP - Inaccurate Data")
| sort - persen
| head 15
```

Keluaran ilustrasi:

```
search_name                              disposition                  count  total  persen
Lab - Proses dari folder user            FP - Incorrect Analytic Logic  41     52     78.8
Lab - Login dari negara tidak lazim      FP - Inaccurate Data           18     30     60.0
```

Cara membacanya: detection pertama bermasalah di logika, jadi perbaikannya ada di search dan allowlist. Detection kedua bermasalah di data, jadi perbaikannya ada di onboarding atau di lookup geolokasi. Dua masalah yang terlihat sama di antrean analyst punya akar yang sangat berbeda.

**Kapan gagal:** nilai `disposition` tersimpan sebagai ID numerik di sebagian versi, sehingga perlu dipetakan lewat lookup bawaan ES. Cek bentuk nilainya sebelum membuat dashboard di atasnya.

### 4.3 Kerangka response plan untuk kasus akun terkompromi

Struktur yang bisa kamu tulis langsung sebagai phase dan task. Isi task ditulis sebagai perintah yang bisa diverifikasi:

```
PHASE 1  Validasi
  T1.1  Pastikan finding bukan hasil uji: cek tiket purple team 24 jam terakhir.
  T1.2  Search: index=lab_auth user=<user> earliest=-7d | stats count BY action src
        Catat: jumlah gagal, waktu sukses pertama, IP sumber.
  T1.3  Cek first-seen IP sumber (lookup lab_first_seen_lookup). Catat umur entitas.

PHASE 2  Penilaian dampak
  T2.1  Search proses di host tujuan 2 jam setelah login sukses.
  T2.2  Cek akses ke share dan aplikasi sensitif oleh akun itu.
  T2.3  Tentukan apakah akun punya hak administratif (Asset and Identity, Day 10).

PHASE 3  Penanggulangan
  T3.1  Reset kredensial dan cabut sesi aktif. Catat nomor tiket.
  T3.2  Blokir IP sumber bila masih aktif. Lampirkan playbook (Day 27).
  T3.3  Konfirmasi dengan pemilik sistem sebelum tindakan yang mengganggu layanan.

PHASE 4  Penutupan dan umpan balik
  T4.1  Tulis note penilaian dengan keyakinan dan keterbatasan.
  T4.2  Beri disposition dan alasan satu baris.
  T4.3  Bila FP: buat tiket tuning. Bila BP: tambah baris allowlist dengan expires_at (Day 32).
  T4.4  Bila TP: usulkan detection atau hunt baru dari apa yang terlewat.
```

Plan diimpor ke ES sebagai JSON, dan JSON adalah satu-satunya format yang didukung [S2]. Cara teraman mendapat struktur JSON yang benar: buat satu plan sederhana di UI, ekspor, lalu pakai hasil ekspor itu sebagai template, karena skemanya bisa berbeda antar versi.

### 4.4 Menambah indikator lewat jalur native dan membuktikannya

Di jalur native, unggah atau unduh daftar indikator lalu biarkan modular input `threatlist` memparsenya ke koleksi KV store [S5]. Pembuktian yang layak dilakukan setiap kali menambah sumber baru:

```
| inputlookup threat_group_intel | stats count BY threat_key
```

```
| inputlookup ip_intel | search ip=203.0.113.50 | table ip threat_key description
```

Nama koleksi bawaan ES untuk tiap tipe indikator berbeda (IP, domain, file hash, dan seterusnya), jadi cek daftar koleksi di dokumentasi versi-mu sebelum menulis dashboard di atasnya [S6]. Setelah indikator masuk, uji end-to-end dengan menghasilkan satu event lab yang memuat indikator itu, lalu pastikan threat matching search menghasilkan finding.

Perhatian yang menghemat satu jam kebingungan: bila kamu memakai jalur native, tab Intelligence di investigation tidak akan menampilkan indikator itu, karena tab tersebut menampilkan data TIM (Cloud) saja [S5].

### 4.5 Mengukur mutu triage sendiri

```
index=notable earliest=-30d
| eval waktu_ambil=review_time-_time, waktu_tutup=close_time-_time
| stats count p50(waktu_ambil) AS p50_ambil_detik p50(waktu_tutup) AS p50_tutup_detik BY urgency
| eval p50_ambil_menit=round(p50_ambil_detik/60,1), p50_tutup_jam=round(p50_tutup_detik/3600,2)
| table urgency count p50_ambil_menit p50_tutup_jam
```

Nama field waktu tinjauan dan penutupan bergantung versi ES, jadi periksa dulu field apa yang tersedia pada satu finding yang sudah tertutup. Yang dicari bukan angka absolut, melainkan dua hal: apakah finding urgency tinggi diambil lebih cepat daripada yang rendah, dan apakah ada finding yang menggantung berhari-hari tanpa pemilik.

### 4.6 Bila lab-mu tidak punya ES

Seluruh pola di Day ini bisa dilatih tanpa ES, karena yang dilatih sebenarnya adalah disiplin kerja:

- Antrean finding diganti alert Wazuh atau hasil scheduled search Splunk Enterprise biasa.
- Investigation diganti satu case di TheHive (Day 19) atau satu file Markdown per kasus.
- Response plan diganti checklist phase dan task di file yang sama, dengan task berisi query lengkap.
- Disposition diganti satu field di catatanmu, dengan nilai yang persis sama seperti di ES supaya kebiasaannya terbawa.

## 5. Lab praktik

**Prasyarat:** ES lab bila ada; bila tidak, Splunk Enterprise plus TheHive atau catatan Markdown. Data autentikasi dan proses dari Day 09 sampai Day 11, serta satu detection dari Day 23.

1. Picu satu detection lab dengan aktivitas jinak (brute force uji ke akun uji, lalu satu login sukses). Pastikan finding muncul di antrean.
2. Jalankan alur bagian 4.1 sampai selesai, termasuk menulis note hipotesis sebelum search pertama.
3. Buat response plan "Akun terkompromi (lab)" dengan empat phase seperti bagian 4.3. Bila di ES, publikasikan lalu pasang ke investigation; bila tidak, pakai sebagai checklist.
4. Tambahkan satu task yang memuat search dan satu task yang memanggil action atau playbook (Day 26 dan Day 27). Catat apa yang berubah dalam kecepatan kerjamu.
5. Tutup investigation dengan disposition dan satu baris alasan. Ulangi untuk dua finding lain dengan disposition berbeda (satu benign positive, satu false positive).
6. Jalankan analisis disposition (bagian 4.2) dan tulis satu paragraf: detection mana yang perlu tuning logika, mana yang perlu perbaikan data.
7. Tambahkan satu indikator fiktif (domain `.example` atau IP dokumentasi `203.0.113.0/24`) lewat jalur threat intelligence yang tersedia di lab-mu, lalu buktikan ia tersimpan dan menghasilkan finding saat event lab memuatnya.
8. Ekspor satu investigation menjadi laporan singkat (satu halaman): ringkasan, timeline, temuan, penilaian dengan keyakinan, keterbatasan, tindakan. Simpan sebagai bahan portofolio dan bahan interview.

**Hasil yang sebaiknya tersimpan:**
- Satu investigation lengkap dengan note bertanggal dan query yang bisa diulang.
- Satu response plan milikmu sendiri (JSON atau Markdown).
- Tabel disposition per detection beserta paragraf keputusan tuning.
- Bukti satu indikator berjalan dari daftar sampai finding.
- Satu laporan investigasi satu halaman.

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa |
|---|---|---|
| Response plan tidak bisa dipasang | Statusnya masih draft, bukan Published | Buka daftar response plan, cek kolom status [S2] |
| Import response plan gagal | Format bukan JSON, atau skema tidak cocok dengan versi | Ekspor plan sederhana dari UI, bandingkan strukturnya |
| Tab Intelligence investigation kosong | Lab memakai native threat intelligence, sedangkan tab itu menampilkan data TIM (Cloud) | Cek koleksi KV store dengan `\| inputlookup` [S5] |
| Indikator tidak menghasilkan finding | Threat matching search tidak aktif, field CIM tidak terisi, atau indikator masuk ke koleksi yang salah | Jalankan threat matching search manual; cek `\| inputlookup <koleksi>` |
| Finding menggantung tanpa pemilik | Tidak ada proses assign di awal shift | Search finding dengan owner kosong dan umur lebih dari sehari |
| Disposition kosong di banyak finding | Penutupan dilakukan tanpa memilih disposition | `index=notable \| stats count BY disposition` termasuk nilai kosong |
| Search di dalam task mengembalikan kosong | Default rentangnya 24 jam terakhir, sedangkan insidennya lebih lama [S4] | Ubah rentang saat menjalankan task |
| Metrik dwell time tidak masuk akal | Timeline insiden dan riwayat pekerjaan tercampur | Pisahkan keduanya di note (bagian 3.3) |

## 7. Kesalahan umum dan jebakan

- Membuat satu investigation per finding untuk insiden yang sama, sehingga metrik dan pekerjaan terpecah.
- Mulai menjalankan search sebelum menulis hipotesis, lalu terjebak mencari yang mendukung dugaan awal.
- Menutup finding tanpa disposition, atau memberi false positive untuk aktivitas yang sebenarnya benign positive.
- Menulis note berisi kesimpulan tanpa query dan rentang waktu, sehingga temuannya tidak bisa diulang.
- Menyalin prosedur kebijakan ke dalam task, sehingga task tidak bisa diverifikasi selesai atau tidak.
- Mengira indikator yang diunggah akan muncul di semua tempat di ES, padahal jalur native dan TIM (Cloud) terpisah.
- Melupakan keterbatasan data di laporan, sehingga "tidak ditemukan bukti" terbaca sebagai "tidak terjadi".
- Membiarkan response plan tidak pernah diperbarui setelah insiden nyata mengajarkan sesuatu yang baru.

## 8. Catatan terkini

- Di ES 8.7, Mission Control adalah antarmuka utama analyst, dan istilah ES 7 (notable, Incident Review) sudah digantikan finding dan analyst queue. Dokumentasi masih memuat kedua istilah di beberapa tempat (Day 20 dan Day 21).
- Response plan bawaan mencakup NIST 800-61 dan Generic Incident Response, dan ES juga menyediakan jalur untuk mengubah dokumen prosedur organisasi menjadi response plan [S3]. Bila fitur itu dipakai, hasilnya tetap perlu ditinjau manusia supaya task-nya bisa diverifikasi.
- Pemisahan native threat intelligence dan Threat Intelligence Management (Cloud) adalah perubahan yang paling sering membuat materi lama salah. Batas lima threat list dan tampilan halaman Intelligence berlaku untuk jalur TIM (Cloud) [S5].
- Nama field pada finding (termasuk field waktu dan disposition) berbeda antar versi ES. Dashboard dan metrik yang dibangun di atasnya perlu dicek ulang setiap upgrade mayor.

## 9. Cheat sheet

```
OBJEK     finding (pemicu) | intermediate finding (jejak risiko) | finding group (kumpulan per entity) | investigation (pekerjaan)
ALUR      assign -> status -> investigation -> note hipotesis -> response plan -> action/playbook -> threat intel -> note penilaian -> disposition -> tutup
NOTE      hipotesis | bukti (query + rentang) | penilaian + keyakinan | keterbatasan | tindakan + pemilik
PLAN      phase > task ; deskripsi Markdown ; task bisa punya action/playbook/search (default 24 jam) ; harus Published ; import JSON saja
DISPOSITION TP | BP (benar, diizinkan -> allowlist ber-expiry) | FP logika (-> perbaiki search) | FP data (-> perbaiki onboarding) | undetermined
INTEL     native: threatlist modular input -> koleksi KV store -> threat matching
          TIM (Cloud): maksimal 5 threat list, observable + prioritization, hanya ini yang tampil di tab Intelligence
UKUR      index=notable | stats count BY search_name disposition ; p50 waktu ambil dan tutup per urgency
TANPA ES  alert Wazuh/scheduled search + case TheHive/Markdown + checklist phase-task + field disposition sendiri
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Overview of Mission Control in Splunk Enterprise Security (ES 8.7) | https://help.splunk.com/en/splunk-enterprise-security-8/user-guide/8.7/mission-control | primer | dilihat 2026-10-09 | Tinggi. Alur kerja analyst dan definisi investigation |
| S2 | Create response plans in Splunk Enterprise Security (ES 8.7) | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/response | primer | dilihat 2026-10-09 | Tinggi. Phase dan task, status Published, import JSON |
| S3 | Included response plans in Splunk Enterprise Security (ES 8.7) | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/response/included-response-plans-in-splunk-enterprise-security | primer | dilihat 2026-10-09 | Tinggi. Daftar plan bawaan termasuk NIST 800-61 |
| S4 | Respond to investigations with response plans in Splunk Enterprise Security (ES 8.7) | https://help.splunk.com/en/splunk-enterprise-security-8/user-guide/8.7/mission-control/respond-to-investigations-with-response-plans-in-splunk-enterprise-security | primer | dilihat 2026-10-09 | Tinggi. Tab Response, task, search default 24 jam, disposition |
| S5 | Configure threat lists in Splunk Enterprise Security (ES 8.7) | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/threat-intelligence/configure-threat-lists-in-splunk-enterprise-security | primer | dilihat 2026-10-09 | Tinggi. Batas lima threat list, berlaku untuk TIM (Cloud), tab Intelligence tidak menampilkan koleksi native |
| S6 | Supported types of threat intelligence in Splunk Enterprise Security (ES 8.7) dan Overview of threat intelligence | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/threat-intelligence | primer | dilihat 2026-10-09 | Tinggi untuk daftar tipe indikator dan modular input `threatlist` |
| S7 | Splunk-Notes Day 16 (annotations), Day 19 (metrik dan disposisi), Day 20 (istilah ES), Day 22 (RBA), Day 23 (detection), Day 26 (adaptive response), Day 27 (SOAR), Day 32 (allowlist dan first-seen) | (lokal) | rujukan internal | 2026-10-09 | Keterkaitan antar Day |

**Catatan sumber:** nama koleksi KV store untuk tiap tipe indikator, nama field waktu pada finding, dan bentuk nilai `disposition` berbeda antar versi ES, jadi tiga hal itu dicek langsung di instance sebelum dipakai di dashboard. Struktur JSON response plan paling aman diperoleh dengan mengekspor plan dari UI versi yang kamu pakai.
