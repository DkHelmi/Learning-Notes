---
day: 11
title: 'Logging, monitoring, dan sinkronisasi waktu: kontrol 8.15-8.17, ekspektasi auditor terhadap SOC, dan pemetaan ke Splunk/Wazuh'
researched_on: 2026-10-10
versions_checked: 'ISO/IEC 27001:2022 + Amd 1:2024; ISO/IEC 27002:2022; ASD/CISA Best Practices for Event Logging and Threat Detection (Agu 2024); NIST SP 800-92 Rev. 1 (masih draft); Splunk Enterprise 10.6; Wazuh 4.14'
---

# Day 11: Logging, monitoring, sinkronisasi waktu, dan ekspektasi auditor terhadap SOC

> Catatan pribadi, bukan materi resmi ISO, dan bukan nasihat hukum atau audit. Perintah dan query di Day ini ditulis untuk dijalankan sendiri di VM lab; keluarannya adalah keluaran ilustrasi.

Cakupan: kontrol 8.15 Logging, 8.16 Monitoring activities, dan 8.17 Clock synchronization, beserta kontrol pendukung (5.33, 8.10, 8.11, 8.2). Day ini juga membahas retensi log, ekspektasi auditor, pemetaan generik ke Splunk dan Wazuh, serta pengecekan waktu di lab.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- menjelaskan beda 8.15 (mencatat), 8.16 (memantau dan menindaklanjuti), dan 8.17 (waktu yang konsisten), serta bukti untuk masing-masing.
- menyusun standar logging yang menyebut sumber wajib, isi minimum, proteksi, dan retensi beserta alasannya.
- memeriksa sinkronisasi waktu di VM Linux dan Windows lab, serta mendeteksi selisih waktu dari data SIEM.
- memetakan kontrol logging dan monitoring ke artefak di Splunk dan Wazuh tanpa menyiratkan bahwa alat tertentu diwajibkan.
- menjawab pertanyaan auditor tentang SOC dengan menyebut proses, bukti, dan pemilik.

## 2. Konteks singkat

Ketiga kontrol ini adalah "rumah" SIEM di Annex A. Namun standar tidak pernah menyebut SIEM. Standar meminta log yang relevan dibuat, dilindungi, dianalisis, dan ditindaklanjuti, dengan waktu yang konsisten. Organisasi kecil bisa memenuhinya dengan alat sederhana, asalkan prosesnya jalan dan bisa dibuktikan.

Auditor jarang menguji konfigurasi teknis secara mendalam. Ia biasanya:

- meminta standar atau kebijakan logging;
- mengambil sampel beberapa sistem dan menanyakan apakah lognya ada di sistem terpusat;
- meminta bukti bahwa log ditinjau dan alert ditindaklanjuti;
- menanyakan siapa yang bisa mengubah atau menghapus log;
- memeriksa apakah jam semua sistem konsisten.

Kapan dipakai: menulis standar logging, onboarding sumber log baru, persiapan audit, dan investigasi yang bergantung pada timeline.
Kapan tidak cukup: kontrol ini tidak memberi daftar use case deteksi. Isi deteksi datang dari risk assessment, threat intelligence (Day 12), dan proses detection engineering organisasi: skenario serangan yang relevan diterjemahkan menjadi rule, diuji, lalu dituning.

## 3. Konsep inti

### 3.1 Tiga kontrol dan pasangannya

| Kontrol | Gagasan inti (kata sendiri) | Pertanyaan auditor |
|---|---|---|
| 8.15 Logging | Log aktivitas, pengecualian, kesalahan, dan event relevan dibuat, disimpan, dilindungi, dan dianalisis | Log apa yang dicatat, di mana disimpan, siapa yang bisa mengubahnya, berapa lama disimpan? |
| 8.16 Monitoring activities | Jaringan, sistem, dan aplikasi dipantau untuk perilaku anomali, lalu event yang berpotensi menjadi insiden dievaluasi | Bagaimana kalian tahu ada yang tidak normal, dan apa yang terjadi setelah alert muncul? |
| 8.17 Clock synchronization | Jam sistem disinkronkan ke sumber waktu yang disetujui | Sumber waktu apa yang dipakai, dan bagaimana kalian tahu semua host sinkron? |

Kontrol pendukung yang sering ikut diperiksa:

- 5.33 Protection of records: log sebagai rekaman bukti;
- 8.10 Information deletion: menghapus log setelah masa retensi;
- 8.11 Data masking: data pribadi di log;
- 8.2 Privileged access rights: aktivitas admin, termasuk admin SIEM;
- 5.25 dan 5.26: tindak lanjut alert sebagai proses insiden.

### 3.2 Kontrol 8.15: apa yang dicatat dan bagaimana dilindungi

Panduan 27002 untuk 8.15 memberi contoh isi log. Catatan ini merangkumnya dengan kata sendiri: identitas pengguna, aktivitas sistem, tanggal dan waktu, identitas perangkat dan lokasi, alamat dan protokol jaringan, percobaan akses berhasil dan gagal, perubahan konfigurasi, penggunaan hak istimewa dan utilitas sistem, alarm dari sistem keamanan, serta aktivasi dan deaktivasi kontrol keamanan. Daftar di teks 27002 bisa sedikit berbeda susunannya; cocokkan sebelum dikutip di standar logging resmi.

Perlindungan log punya tiga sisi:

1. **Integritas:** log tidak bisa diubah tanpa jejak. Caranya antara lain penyimpanan terpusat, hak akses terbatas, dan penyimpanan write-once atau hash.
2. **Aktivitas admin:** orang yang mengelola sistem tidak boleh bebas menghapus log aktivitasnya sendiri. Ini terkait 5.3 Segregation of duties dan 8.2.
3. **Kerahasiaan:** log bisa memuat data pribadi atau rahasia, sehingga aksesnya dibatasi dan, bila perlu, datanya disamarkan (8.11).

Perhatian: beberapa artikel vendor menulis seolah-olah 8.15 mewajibkan pengiriman real-time ke SIEM, dan 8.16 mewajibkan UEBA [S7]. Itu interpretasi praktik yang baik, bukan bunyi standar. Untuk audit, yang penting adalah risiko tertangani dan buktinya ada.

### 3.3 Kontrol 8.16: memantau, bukan hanya mengumpulkan

8.16 adalah kontrol baru di 2022. Panduannya mencakup [S4]:

- **Apa yang dipantau:** lalu lintas jaringan masuk dan keluar, akses ke sistem penting (termasuk sistem monitoring itu sendiri), log dan konfigurasi perangkat keamanan, integritas kode yang dijalankan, serta pemakaian sumber daya.
- **Baseline perilaku normal:** pola akses dan pemakaian jaringan pada jam kerja biasa, supaya penyimpangan bisa dikenali.
- **Anomali yang dicari:** proses berhenti tiba-tiba, lalu lintas ke alamat atau domain bermasalah, teknik intrusi yang dikenal, akses tidak sah, pemindaian, dan percobaan akses ke sumber daya penting.
- **Tindak lanjut:** event yang mencurigakan masuk ke penilaian 5.25 dan respons 5.26 [S4].

Bagi SOC, bukti 8.16 adalah daftar rule atau use case aktif yang terhubung ke risiko, tiket yang lahir dari alert, dan catatan tuning. Kalimat "kami punya SIEM" bukan bukti 8.16. Kalimat "kami punya 120 rule aktif; bulan lalu 340 alert, 41 menjadi insiden, dan 6 rule dituning karena false positive" adalah bukti.

### 3.4 Kontrol 8.17: waktu yang bisa dipercaya

Tanpa waktu yang konsisten, timeline insiden bisa salah urut dan korelasi lintas sumber gagal. Panduan 8.17 mencakup [S4]:

- sumber waktu acuan yang disetujui, misalnya server NTP internal yang mengambil waktu dari sumber eksternal tepercaya;
- protokol NTP atau PTP;
- dua sumber waktu terpisah untuk ketahanan;
- untuk lingkungan hybrid dan cloud, mencatat perbedaan sumber waktu antara sistem yang dikelola sendiri dan yang dikelola penyedia cloud.

Panduan ASD dan CISA (Agustus 2024) juga menekankan sumber waktu yang akurat dan konsisten, serta konsistensi format timestamp di seluruh perangkat, supaya event bisa dikorelasikan [S2]. Praktik umum di SOC adalah menyimpan timestamp dalam UTC dan menampilkannya dalam zona waktu lokal saat dibaca.

### 3.5 Retensi log

Standar tidak menetapkan angka retensi. Retensi ditentukan oleh:

- persyaratan hukum, regulasi, dan kontrak (4.2 dan 5.31);
- kebutuhan investigasi. ASD dan CISA menyebut retensi yang lebih panjang membantu menilai cakupan insiden, karena penyusup sering bertahan lama sebelum terdeteksi [S2];
- biaya storage dan risiko menyimpan data pribadi terlalu lama (8.10, 8.11).

Contoh konfigurasi di alat (fakta teknis, bukan rekomendasi angka):

- **Splunk:** retensi per index diatur lewat `frozenTimePeriodInSecs` di `indexes.conf`. Nilai default-nya 188697600 detik, yaitu 2.184 hari atau 6 x 364 hari, sekitar 6 tahun [S6]. Data dihapus saat bucket digulung ke frozen bila tidak ada skrip arsip. Satu bucket baru digulung bila semua event di dalamnya sudah melewati batas, jadi data bisa bertahan sedikit lebih lama dari angka itu [S6].
- **Wazuh 4.14:** retensi index diatur lewat kebijakan Index State Management (ISM) di dashboard, lewat menu Indexer management > Index Management > State management policies. Kebijakan diterapkan ke pola index seperti `wazuh-alerts-*` dengan kondisi umur minimum (contoh dokumentasi memakai 90 hari), lalu index dihapus [S5].

Konsekuensi audit: angka retensi di standar logging harus cocok dengan konfigurasi nyata. Standar menulis 365 hari, tetapi ISM policy menghapus setelah 90 hari? Itu nonconformity yang mudah ditemukan.

### 3.6 Kebijakan logging tingkat organisasi

Panduan ASD dan CISA merangkum empat langkah utama [S1][S2]:

1. kebijakan logging yang disetujui organisasi;
2. pengumpulan dan korelasi log secara terpusat;
3. penyimpanan aman dan integritas log;
4. strategi deteksi untuk ancaman yang relevan, termasuk teknik living off the land.

Keempatnya cocok dengan 8.15 (langkah 1-3) dan 8.16 (langkah 4). Panduan ini dari lembaga pemerintah, jadi bisa dipakai sebagai acuan praktik yang kredibel saat menulis standar logging untuk ISMS.

NIST juga sedang merevisi panduan log management. SP 800-92 Rev. 1 (Cybersecurity Log Management Planning Guide) dirilis sebagai draft publik awal pada 11 Oktober 2023 [S3]. Per Oktober 2026, halaman publikasinya masih mencantumkan draft itu sebagai versi terakhir, jadi SP 800-92 (2006) tetap versi final yang berlaku.

### 3.7 Pemetaan generik ke Splunk dan Wazuh

| Kontrol | Artefak di Splunk | Artefak di Wazuh | Bukti untuk auditor |
|---|---|---|---|
| 8.15 isi log | Daftar index dan sourcetype per sumber | Daftar agent dan sumber log di konfigurasi | Inventaris sumber log terhubung ke daftar aset in-scope |
| 8.15 proteksi | Role dan capability; audit trail di index `_audit` | Role di dashboard; akses ke indexer | Daftar siapa yang bisa menghapus data; log aktivitas admin |
| 8.15 retensi | `frozenTimePeriodInSecs` per index | Kebijakan ISM | Tangkapan konfigurasi yang cocok dengan standar |
| 8.16 deteksi | Saved search dan correlation search atau detection aktif | Rule bawaan dan rule kustom | Daftar rule terhubung ke risiko; statistik alert |
| 8.16 tindak lanjut | Alert ke tiket atau notable/finding di ES | Alert ke integrasi tiket atau SOAR | Sampel tiket dengan keputusan triage |
| 8.17 waktu | Lag `_indextime` minus `_time` per host | Timestamp alert dibandingkan waktu agent | Laporan host dengan selisih waktu |

Tabel ini generik dan sengaja tidak masuk ke detail konfigurasi alat. Nama menu dan fitur bisa berbeda antar versi, jadi cek nama menu di versi lab-mu.

## 4. Contoh dokumen, perintah, dan query (organisasi fiktif dan lab)

Organisasi fiktif: PT Awan Nusantara (PT AN). Semua keluaran di bagian ini adalah keluaran ilustrasi, bukan hasil eksekusi nyata.

### 4.1 Cuplikan standar logging PT AN

```
STD-LOG-01 Standar Logging dan Monitoring, v1.0 (pemilik: Lead SOC; penyetuju: ISMS Manager)
1. Sumber wajib: hypervisor, firewall perimeter, VPN, AD/IdP, server Linux/Windows in-scope,
   panel manajemen, SIEM itu sendiri (audit trail admin).
2. Isi minimum: waktu (UTC), host, user, aksi, hasil (berhasil/gagal), IP sumber/tujuan.
3. Waktu: semua host in-scope sinkron ke ntp1/ntp2.internal; selisih maksimal 1 detik.
4. Retensi: online 180 hari; arsip 1 tahun (total 545 hari). Alasan: kontrak klien perbankan dan kebutuhan investigasi.
5. Proteksi: hanya role SIEM-Admin yang dapat mengubah retensi; perubahan wajib tiket;
   admin SIEM tidak dapat menghapus audit trail tanpa persetujuan ISMS Manager.
6. Data pribadi: nomor identitas dan nomor telepon pelanggan disamarkan sebelum diindeks (8.11).
7. Tinjauan: Lead SOC meninjau cakupan log dan statistik alert setiap bulan (rekaman: REC-03).
```

Angka 545 hari berasal dari 180 + 365. Setiap angka di standar harus bisa ditelusuri ke alasannya, karena auditor akan menanyakan "kenapa 180?".

### 4.2 Inventaris sumber log (cuplikan)

| Sumber | Aset in-scope | Dikirim ke | Format waktu | Pemilik | Terakhir diverifikasi |
|---|---|---|---|---|---|
| Firewall perimeter | fw-jkt1-01, fw-jkt1-02 | SIEM via syslog | UTC | Network Eng | 2026-09-30 |
| VPN appliance | vpn-jkt1-01 | SIEM via syslog | Waktu lokal (WIB) | Network Eng | 2026-09-30 |
| Hypervisor | hv-jkt1-01 sampai 08 | Wazuh agent | UTC | Platform | 2026-09-28 |
| AD/IdP | dc-01, dc-02 | Splunk UF | UTC | IT Ops | 2026-09-29 |

Baris VPN memakai waktu lokal, berbeda dari yang lain. Ini temuan kecil yang harus ditangani: normalisasi di parser, atau ubah konfigurasi perangkat. Bila tidak, korelasi login VPN dengan login AD akan meleset 7 jam.

### 4.3 Perintah cek sinkronisasi waktu (dijalankan di VM lab)

**Linux (systemd):**

```
timedatectl status
```

- **Tujuan:** melihat jam sistem, zona waktu, dan apakah sinkronisasi NTP aktif.
- **Bagian penting:** baris `System clock synchronized` menunjukkan status sinkronisasi; `NTP service` menunjukkan layanan sinkronisasi aktif atau tidak; `Time zone` menunjukkan zona waktu sistem.
- **Keluaran ilustrasi:**

```
               Local time: Thu 2026-10-08 14:05:12 WIB
           Universal time: Thu 2026-10-08 07:05:12 UTC
                Time zone: Asia/Jakarta (WIB, +0700)
System clock synchronized: yes
              NTP service: active
```

- **Cara membaca:** selisih Local time dan Universal time harus 7 jam untuk WIB. `synchronized: yes` berarti jam sudah tersinkron ke sumber.
- **Variasi:** bila VM memakai chrony, `chronyc tracking` menampilkan sumber acuan dan offset terakhir; `chronyc sources` menampilkan daftar server waktu.
- **Kapan gagal:** VM tanpa systemd tidak punya `timedatectl`. VM lab yang terisolasi tanpa akses ke server NTP akan menunjukkan `synchronized: no`; di lab, kamu bisa menjadikan satu VM sebagai server NTP internal.

**Windows:**

```
w32tm /query /status
```

- **Tujuan:** melihat sumber waktu dan waktu sinkronisasi terakhir layanan Windows Time.
- **Bagian penting:** `Source` menunjukkan sumber waktu; `Last Successful Sync Time` menunjukkan kapan terakhir berhasil.
- **Cara membaca:** `Source` berisi `Local CMOS Clock` berarti mesin tidak sinkron ke sumber eksternal. Ini temuan 8.17.
- **Variasi:** `w32tm /query /peers` menampilkan daftar peer. Di domain, klien biasanya sinkron ke domain controller.
- **Kapan gagal:** perintah butuh prompt dengan hak yang cukup di beberapa konfigurasi. Cek keluaran persis di versi Windows lab-mu.

### 4.4 Query Splunk untuk mendeteksi selisih waktu per host

```
index=* earliest=-24h
| eval lag_sec=_indextime-_time
| stats median(lag_sec) as median_lag min(lag_sec) as min_lag max(lag_sec) as max_lag count by host
| where abs(median_lag) > 60 OR min_lag < -5
| sort - max_lag
```

- **Tujuan:** menemukan host yang jamnya kemungkinan tidak sinkron, dengan membandingkan waktu event (`_time`) dan waktu Splunk mengindeks event (`_indextime`).
- **Penjelasan:**
  - `lag_sec` positif berarti event diindeks setelah waktu kejadian, dan ini normal (ada jeda kirim).
  - `lag_sec` negatif berarti waktu event lebih maju dari waktu indeks. Biasanya jam host terlalu cepat, atau zona waktu salah tafsir.
  - `median_lag` yang sangat besar (misalnya sekitar 25200 detik, yaitu 7 jam) biasanya tanda timestamp waktu lokal dibaca sebagai UTC.
- **Keluaran ilustrasi:**

```
host          median_lag  min_lag  max_lag  count
vpn-jkt1-01        25204    25190    25260    812
hv-jkt1-05            -42      -45       -3   4021
```

- **Cara membaca:** `vpn-jkt1-01` tertinggal sekitar 25200 detik, cocok dengan temuan zona waktu di bagian 4.2. `hv-jkt1-05` punya lag negatif sekitar 42 detik, jadi jam host itu kemungkinan maju sekitar 40 detik. Cek NTP di host tersebut.
- **Variasi:** ganti `host` dengan `sourcetype` untuk melihat masalah per jenis sumber.
- **Kapan gagal:** `index=*` pada data besar sangat berat, jadi batasi index atau rentang waktu di lingkungan nyata. Data yang dikirim batch (misalnya log yang dibaca ulang dari file lama) akan menunjukkan lag positif besar walaupun jamnya benar. Bila lab-mu memakai dataset statis lama (misalnya BOTS), query ini tidak bermakna karena waktu indeks jauh setelah waktu event; pakai data live dari VM lab.

### 4.5 Rekaman tinjauan log bulanan (bukti 8.15 dan 8.16)

```
REC-03 Tinjauan logging dan monitoring, September 2026 (peninjau: Lead SOC)
Cakupan sumber log in-scope : 49 dari 50 host (98%); 1 host (vpn-jkt1-01) zona waktu salah -> CA-2026-019
Alert                       : 340 alert, 41 insiden (12%), 6 rule dituning (FP tinggi)
Waktu                       : 1 host selisih lebih dari 1 detik (hv-jkt1-05) -> tiket OPS-5521
Retensi                     : konfigurasi index dan ISM cocok dengan STD-LOG-01 (dicek 2026-09-30)
Akses admin SIEM            : 0 perubahan retensi tanpa tiket (audit trail ditinjau)
```

Angka 41 dari 340 sama dengan sekitar 12%. Rekaman ini sekaligus menjadi bukti 9.1 dan input management review.

## 5. Lab praktik (di VM lab terisolasi)

Simpan dokumen di `ISO27001-note/latihan/day11-<nama-org-fiktif>.md`. Jalankan perintah hanya di VM lab milikmu.

1. Tulis standar logging versi organisasi fiktifmu dengan format bagian 4.1. Setiap angka (retensi, selisih waktu) punya alasan tertulis.
2. Buat inventaris sumber log dari lab-mu: setiap VM atau perangkat, ke mana lognya dikirim (Splunk atau Wazuh), format waktunya, dan kapan terakhir diverifikasi.
3. Jalankan `timedatectl status` (Linux) dan `w32tm /query /status` (Windows) di VM lab. Catat hasilnya dan tandai VM yang tidak sinkron.
4. Bila lab-mu punya Splunk dengan data live, jalankan query bagian 4.4 dengan index yang kamu punya. Catat host dengan lag negatif atau median sangat besar.
5. Periksa retensi di lab: lihat nilai `frozenTimePeriodInSecs` untuk index yang kamu pakai di Splunk, atau kebijakan ISM di Wazuh. Bandingkan dengan angka di standar logging-mu.
6. Periksa siapa yang bisa menghapus data atau mengubah retensi di SIEM lab. Catat sebagai bukti 8.15 atau sebagai temuan.
7. Tulis rekaman tinjauan bulanan seperti bagian 4.5 berdasarkan hasil langkah 2-6.
8. Tulis jawaban 2 menit untuk pertanyaan auditor: "Bagaimana kalian memastikan log yang relevan tersedia, terlindungi, ditinjau, dan waktunya konsisten?"

**Hasil yang seharusnya teramati:** standar logging, inventaris, dan rekaman tinjauan yang memakai data dari lab-mu sendiri, termasuk minimal satu temuan nyata (VM tidak sinkron, retensi tidak cocok, atau akses admin terlalu luas).

**Hasil yang sebaiknya tersimpan:**
- Setiap angka di standar logging punya alasan.
- Inventaris mencakup semua VM lab dan format waktunya.
- Hasil cek waktu dari minimal satu VM Linux dan satu VM Windows tercatat.
- Retensi di konfigurasi dibandingkan dengan standar.
- Rekaman tinjauan berisi angka yang dihitung ulang.
- Tidak ada log atau data dari sistem kerja yang dipakai.

**Variasi tantangan:** ubah zona waktu satu VM lab menjadi salah (dengan snapshot dulu), kirim beberapa event, lalu tunjukkan bagaimana query bagian 4.4 menangkapnya. Kembalikan snapshot setelah selesai.

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Timeline insiden tidak masuk akal (respons sebelum serangan) | Zona waktu salah tafsir atau jam host tidak sinkron | Query lag bagian 4.4; cek `timedatectl` atau `w32tm` di host |
| Retensi di standar berbeda dengan konfigurasi | Standar ditulis tanpa melihat konfigurasi | Tinjau keduanya bersama setiap kuartal; catat di rekaman tinjauan |
| Auditor menemukan admin bisa menghapus log tanpa jejak | Role SIEM terlalu luas | Pisahkan peran; kirim audit trail ke penyimpanan terpisah |
| Banyak alert tetapi tidak ada insiden tercatat | Alert tidak terhubung ke proses 5.25 | Wajibkan setiap alert prioritas tinggi punya tiket dan keputusan |
| VM lab selalu tidak sinkron | Lab terisolasi tanpa sumber NTP | Jadikan satu VM sebagai server NTP internal lab |

## 7. Kesalahan umum dan jebakan

- Menganggap ISO 27001 mewajibkan SIEM tertentu atau UEBA. Standar meminta hasil dan bukti, bukan merek alat [S7].
- Mengumpulkan log tanpa pernah meninjaunya. Itu memenuhi sebagian 8.15, tetapi tidak 8.16.
- Menulis retensi di kebijakan tanpa mencocokkannya dengan konfigurasi Splunk atau Wazuh.
- Lupa bahwa SIEM sendiri juga sistem in-scope: aktivitas admin SIEM harus dicatat dan dilindungi.
- Mencampur zona waktu antar sumber tanpa normalisasi.
- Menyimpan data pribadi di log tanpa masking atau batas akses, sehingga 8.11 dan UU PDP ikut terdampak.
- `[komunitas]` Pengguna Splunk sering kaget karena data bertahan lebih lama dari `frozenTimePeriodInSecs`. Penyebabnya, bucket baru digulung ke frozen saat event terbarunya sudah melewati batas [S6].

## 8. Catatan terkini

- ASD's ACSC, CISA, FBI, NSA, dan mitra internasional menerbitkan Best Practices for Event Logging and Threat Detection pada 21 Agustus 2024 [S1]. Panduan ini cocok dipakai sebagai acuan standar logging.
- NIST SP 800-92 Rev. 1 masih berstatus draft sejak Oktober 2023 [S3]. SP 800-92 (2006) masih menjadi versi final terakhir.
- Dokumentasi Wazuh 4.14 menempatkan retensi index di Index State Management dengan contoh 90 hari [S5].
- Penulis materi lain sering memakai istilah "clock synchronisation" (ejaan Inggris Britania). Judul resmi di 27001:2022 memakai "Clock synchronization". Cek ejaan di teks resmi.

## 9. Cheat sheet

```
8.15 Logging  : catat (siapa, apa, kapan, di mana, hasil) | simpan | lindungi (integritas, admin, kerahasiaan) | analisis
8.16 Monitoring: pantau + baseline normal + cari anomali -> 5.25 nilai -> 5.26 respons ; bukti: rule, tiket, tuning
8.17 Waktu    : sumber acuan disetujui, NTP/PTP, 2 sumber, catat beda cloud ; simpan UTC
Pendukung     : 5.33 records | 8.10 deletion | 8.11 masking | 8.2 privileged | 5.3 SoD
Retensi       : tidak ada angka di standar; dasar = hukum/kontrak + investigasi + biaya + privasi
  Splunk: frozenTimePeriodInSecs (default 188697600 s = 2184 hari = 6 x 364) per index di indexes.conf
  Wazuh 4.14: ISM policy (Indexer management > Index Management > State management policies), min_index_age
ASD/CISA 2024: kebijakan logging | terpusat + korelasi | penyimpanan aman + integritas | strategi deteksi
Cek waktu: timedatectl status | chronyc tracking | w32tm /query /status
Splunk lag: eval lag_sec=_indextime-_time ; negatif = jam host maju ; ~25200 = WIB dibaca UTC
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | CISA: ASD's ACSC, CISA, FBI, and NSA release Best Practices for Event Logging and Threat Detection | https://cisa.gov/news-events/alerts/2024/08/21/asds-acsc-cisa-fbi-and-nsa-support-international-partners-release-best-practices-event-logging-and | primer (lembaga pemerintah) | 2024-08-21; diakses 2026-10-08 | Tinggi untuk fakta rilis dan cakupan |
| S2 | ASD's ACSC: Best practices for event logging and threat detection | https://www.cyber.gov.au/business-government/detecting-responding-to-threats/event-logging/best-practices-event-logging-threat-detection | primer (lembaga pemerintah) | 2024 | Sedang-tinggi. Empat langkah, sumber waktu, retensi; rincian di bagian 3.4-3.6 adalah ringkasan, cocokkan dengan PDF panduan bila dikutip |
| S3 | NIST CSRC: Log management project news (SP 800-92r1 draft) | https://csrc.nist.gov/Projects/log-management/news | primer (NIST) | draft 2023-10-11; diakses 2026-10-08 | Tinggi untuk tanggal dan status draft |
| S4 | ISMS.online: ISO 27002 control 8.17 dan 8.16 | https://www.isms.online/iso-27002/control-8-16-monitoring-activities/ | sekunder (vendor) | 2025-07-25; diakses 2026-10-08 | Sedang. Panduan 8.16 dan 8.17 dalam ringkasan vendor |
| S5 | Wazuh documentation 4.14: Index lifecycle management | https://documentation.wazuh.com/4.14/user-manual/wazuh-indexer-cluster/index-lifecycle-management.html | primer (dokumentasi resmi) | versi 4.14; diakses 2026-10-08 | Tinggi. Menu dan contoh kebijakan retensi |
| S6 | Splunk Community: Why is frozenTimePeriodInSecs 188697600? | https://community.splunk.com/t5/Getting-Data-In/Why-is-frozenTimePeriodInSecs-188697600/td-p/160360 | komunitas | diakses 2026-10-08 | Sedang. Nilai default dan perilaku bucket; nilai default juga tercantum di spesifikasi indexes.conf, cek di dokumentasi Splunk 10.6 |
| S7 | Bemopro: ISO 27001 audit logging requirements | https://www.bemopro.com/compliance-requirements/iso-27001-audit-logging | sekunder (vendor) | diakses 2026-10-08 | Rendah-sedang. Dipakai sebagai contoh interpretasi berlebihan (SIEM real-time, UEBA) |
| S8 | ISMS.online: ISO 27002 control 8.17 clock synchronisation | https://www.isms.online/iso-27002/control-8-17-clock-synchronisation | sekunder (vendor) | 2025-07-25; diakses 2026-10-08 | Sedang. Dua sumber waktu, catatan untuk cloud |

**Catatan sumber:** daftar isi log di bagian 3.2 dan panduan 8.16-8.17 di bagian 3.3-3.4 adalah rangkuman dari sumber sekunder, bukan dari teks 27002; cocokkan sebelum dikutip di dokumen resmi. Rincian panduan ASD/CISA [S1][S2] di bagian 3.4-3.6 adalah ringkasan dan perlu dicocokkan dengan PDF panduannya bila dikutip. Perintah dan query belum dijalankan; keluarannya ilustrasi.
