---
day: 11
title: 'Logging, monitoring, dan sinkronisasi waktu: kontrol 8.15-8.17, ekspektasi auditor terhadap SOC, dan pemetaan ke Splunk/Wazuh'
researched_on: 2026-10-10
versions_checked: 'ISO/IEC 27001:2022 + Amd 1:2024; ISO/IEC 27002:2022; ASD/CISA Best Practices for Event Logging and Threat Detection (21 Agu 2024); NIST SP 800-92 Rev. 1 (initial public draft 11 Okt 2023, belum final); Splunk Enterprise 10.6; Wazuh 4.14'
---

# Day 11: Logging, monitoring, sinkronisasi waktu, dan ekspektasi auditor terhadap SOC

Cakupan: kontrol 8.15 Logging, 8.16 Monitoring activities, dan 8.17 Clock synchronization beserta kontrol pendukungnya, retensi log, ekspektasi auditor, pemetaan generik ke Splunk dan Wazuh, serta pengecekan waktu di VM lab.

> Catatan pribadi, bukan materi resmi ISO, dan bukan nasihat hukum atau audit. Perintah dan query di Day ini ditulis untuk dijalankan sendiri di VM lab; keluarannya adalah keluaran ilustrasi.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- menjelaskan beda 8.15 (mencatat), 8.16 (memantau dan menindaklanjuti), dan 8.17 (waktu yang konsisten), serta bukti untuk masing-masing.
- menyusun standar logging yang menyebut sumber wajib, isi minimum, proteksi, dan retensi beserta alasannya.
- memeriksa sinkronisasi waktu di VM Linux dan Windows lab, serta mendeteksi selisih waktu dari data SIEM.
- memetakan kontrol logging dan monitoring ke artefak di Splunk dan Wazuh tanpa menyiratkan bahwa alat tertentu diwajibkan.
- menjawab pertanyaan auditor tentang SOC dengan menyebut proses, bukti, dan pemilik.

## 2. Konteks singkat

Ketiga kontrol ini adalah "rumah" SIEM di Annex A, walaupun standar tidak pernah menyebut SIEM. Yang diminta: log yang relevan dibuat, dilindungi, dianalisis, dan ditindaklanjuti, dengan waktu yang konsisten; alat sederhana pun cukup bila prosesnya jalan dan terbukti.

Auditor jarang menguji konfigurasi secara mendalam. Ia meminta standar logging, mengambil sampel sistem untuk dicek di log terpusat, meminta bukti tindak lanjut alert, menanyakan siapa yang bisa menghapus log, dan memeriksa konsistensi jam.

Kapan dipakai: menulis standar logging, onboarding sumber log baru, persiapan audit, dan investigasi yang bergantung pada timeline.
Kapan tidak cukup: kontrol ini tidak memberi daftar use case deteksi; isinya datang dari risk assessment, threat intelligence (Day 12), dan detection engineering.

## 3. Konsep inti

### 3.1 Tiga kontrol dan pasangannya

| Kontrol | Gagasan inti (kata sendiri) | Pertanyaan auditor |
|---|---|---|
| 8.15 Logging | Log aktivitas, pengecualian, kesalahan, dan event relevan dibuat, disimpan, dilindungi, dan dianalisis | Log apa yang dicatat, di mana disimpan, siapa yang bisa mengubahnya, berapa lama disimpan? |
| 8.16 Monitoring activities | Jaringan, sistem, dan aplikasi dipantau untuk perilaku anomali, lalu event yang berpotensi menjadi insiden dievaluasi | Bagaimana kalian tahu ada yang tidak normal, dan apa yang terjadi setelah alert muncul? |
| 8.17 Clock synchronization | Jam sistem disinkronkan ke sumber waktu yang disetujui | Sumber waktu apa yang dipakai, dan bagaimana kalian tahu semua host sinkron? |

8.15 menggabungkan tiga kontrol edisi 2013 (A.12.4.1 Event logging, A.12.4.2 Protection of log information, A.12.4.3 Administrator and operator logs), 8.17 adalah penerus A.12.4.4, sedangkan 8.16 adalah satu dari 11 kontrol baru di edisi 2022 (Day 08).

Kontrol pendukung yang sering ikut diperiksa: 5.33 Protection of records (log sebagai rekaman), 8.10 Information deletion (penghapusan setelah retensi), 8.11 Data masking (data pribadi di log), 8.2 Privileged access rights (termasuk admin SIEM), 5.3 Segregation of duties, serta 5.25 dan 5.26 untuk tindak lanjut alert.

### 3.2 Kontrol 8.15: apa yang dicatat dan bagaimana dilindungi

Panduan 27002 untuk 8.15 meminta setiap entri log memuat identitas pengguna, aktivitas sistem, tanggal dan waktu, identitas perangkat atau sistem beserta lokasinya, serta alamat dan protokol jaringan [S9]. Event yang dianjurkan dicatat [S9]:

- percobaan akses sistem, berhasil maupun gagal;
- percobaan akses data dan sumber daya lain, berhasil maupun gagal;
- perubahan konfigurasi sistem;
- penggunaan hak istimewa, utilitas sistem, dan aplikasi;
- file yang diakses dan jenis aksesnya, termasuk penghapusan;
- alarm kontrol akses dan interupsi kritis;
- aktivasi dan deaktivasi sistem keamanan seperti antivirus dan IDS;
- pembuatan, perubahan, dan penghapusan identitas;
- transaksi yang dijalankan pengguna di aplikasi.

Perlindungan log punya tiga sisi:

1. **Integritas:** log tidak bisa diubah tanpa jejak, termasuk ketika storage penuh atau jaringan gagal sehingga log tertimpa atau tidak terbentuk. Cara yang disebut panduan: hash kriptografis, penyimpanan append-only atau read-only, dan file transparansi publik [S9].
2. **Aktivitas admin:** pengguna, termasuk yang punya hak istimewa, tidak boleh bisa menghapus atau menonaktifkan log aktivitasnya sendiri [S9]. Ini terkait 5.3 dan 8.2.
3. **Kerahasiaan:** log bisa memuat data pribadi atau rahasia, sehingga aksesnya dibatasi dan, bila log dibagikan ke vendor, username, IP, dan hostname disamarkan (8.11) [S9].

Perhatian: beberapa artikel vendor menulis seolah-olah 8.15 mewajibkan pengiriman real-time ke SIEM dan 8.16 mewajibkan UEBA [S7]. Itu praktik yang baik, bukan bunyi standar.

### 3.3 Kontrol 8.16: memantau, bukan hanya mengumpulkan

Panduan 8.16 mencakup [S4]:

- **Apa yang dipantau:** lalu lintas jaringan masuk dan keluar, akses ke sistem penting (termasuk sistem monitoring itu sendiri), log dan konfigurasi perangkat keamanan, integritas kode yang dijalankan, serta pemakaian sumber daya.
- **Baseline perilaku normal:** pola akses dan pemakaian jaringan pada jam kerja biasa, supaya penyimpangan bisa dikenali.
- **Anomali yang dicari:** proses berhenti tiba-tiba, lalu lintas ke alamat atau domain bermasalah, teknik intrusi yang dikenal, akses tidak sah, dan pemindaian.
- **Tindak lanjut:** event mencurigakan masuk ke penilaian 5.25 dan respons 5.26.

Bukti 8.16 adalah daftar rule aktif yang terhubung ke risiko, tiket dari alert, dan catatan tuning. "Kami punya SIEM" bukan bukti. "Kami punya 120 rule aktif; bulan lalu 340 alert, 41 menjadi insiden, dan 6 rule dituning karena false positive" adalah bukti.

### 3.4 Kontrol 8.17: waktu yang bisa dipercaya

Tanpa waktu konsisten, timeline salah urut dan korelasi gagal. Panduan 8.17 mencakup [S8]:

- satu sumber waktu acuan yang disetujui, misalnya siaran waktu radio yang terhubung ke jam atom, lalu diteruskan ke jaringan oleh server NTP internal;
- protokol NTP atau PTP;
- pertimbangan dua sumber waktu terpisah untuk ketahanan;
- untuk cloud, sumber waktu penyedia bisa berbeda dari on-premise, jadi selisihnya dipantau berkala dan dicatat agar tidak membingungkan investigasi.

Panduan ASD dan CISA (2024) juga menekankan sumber waktu akurat dan format timestamp konsisten [S2]. Praktik umum SOC: simpan dalam UTC, tampilkan dalam zona lokal.

### 3.5 Retensi log

Standar tidak menetapkan angka retensi. Retensi ditentukan oleh:

- persyaratan hukum, regulasi, dan kontrak (4.2 dan 5.31);
- kebutuhan investigasi. ASD dan CISA menyebut retensi yang lebih panjang membantu menilai cakupan insiden, karena penyusup sering bertahan lama sebelum terdeteksi [S2];
- biaya storage dan risiko menyimpan data pribadi terlalu lama (8.10, 8.11).

Konfigurasi di alat (fakta teknis, bukan rekomendasi angka):

- **Splunk:** retensi per index diatur lewat `frozenTimePeriodInSecs` di `indexes.conf`. Default-nya 188697600 detik, yaitu 2.184 hari (6 x 364 hari, sekitar 6 tahun) [S6]. Tanpa skrip arsip atau `coldToFrozenDir`, data dihapus saat bucket digulung ke frozen. Bucket baru digulung bila event terbarunya sudah melewati batas, jadi data bisa bertahan lebih lama dari angka itu [S6]. Nilai efektif per index di lab bisa dilihat dengan `splunk btool indexes list <nama_index> --debug`.
- **Wazuh 4.14:** retensi index diatur lewat kebijakan Index State Management (ISM) di dashboard: menu Indexer management > Index Management > State management policies > Create policy. Contoh dokumentasi menerapkan kebijakan ke pola `wazuh-alerts-*` dengan `min_index_age` 90 hari lalu menghapus index; `ism_template` membuat kebijakan otomatis berlaku untuk index baru, sedangkan index lama perlu Actions > Apply policy [S5].

Angka retensi di standar harus cocok dengan konfigurasi. Standar menulis 365 hari, tetapi kebijakan ISM menghapus setelah 90 hari, adalah nonconformity yang mudah ditemukan.

### 3.6 Kebijakan logging tingkat organisasi

Panduan ASD, CISA, dan mitra internasional merangkum empat pertimbangan utama [S1][S2]:

1. kebijakan logging yang disetujui organisasi;
2. akses dan korelasi log secara terpusat;
3. penyimpanan aman dan integritas log;
4. strategi deteksi untuk ancaman yang relevan, termasuk teknik living off the land.

Langkah 1-3 cocok dengan 8.15 dan langkah 4 dengan 8.16, sehingga panduan pemerintah ini acuan praktik yang kredibel untuk standar logging.

NIST SP 800-92 Rev. 1 (Cybersecurity Log Management Planning Guide) dirilis sebagai initial public draft pada 11 Oktober 2023 dengan masa komentar sampai 29 November 2023 [S3]. Per Oktober 2026 belum ada draft kedua atau versi final, jadi SP 800-92 (2006) tetap versi final yang berlaku.

### 3.7 Pemetaan generik ke Splunk dan Wazuh

| Kontrol | Artefak di Splunk | Artefak di Wazuh | Bukti untuk auditor |
|---|---|---|---|
| 8.15 isi log | Daftar index dan sourcetype per sumber | Daftar agent dan sumber log di konfigurasi | Inventaris sumber log terhubung ke daftar aset in-scope |
| 8.15 proteksi | Role dan capability; audit trail di index `_audit` | Role di dashboard; akses ke indexer | Daftar siapa yang bisa menghapus data; log aktivitas admin |
| 8.15 retensi | `frozenTimePeriodInSecs` per index | Kebijakan ISM | Tangkapan konfigurasi yang cocok dengan standar |
| 8.16 deteksi | Saved search dan correlation search atau detection aktif | Rule bawaan dan rule kustom | Daftar rule terhubung ke risiko; statistik alert |
| 8.16 tindak lanjut | Alert ke tiket atau notable/finding di ES | Alert ke integrasi tiket atau SOAR | Sampel tiket dengan keputusan triage |
| 8.17 waktu | Lag `_indextime` minus `_time` per host | Timestamp alert dibandingkan waktu agent | Laporan host dengan selisih waktu |

## 4. Contoh dokumen, perintah, dan query (organisasi fiktif dan lab)

Organisasi fiktif: PT Awan Nusantara (PT AN). Semua keluaran di bagian ini adalah keluaran ilustrasi.

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

Angka 545 hari berasal dari 180 + 365. Auditor akan bertanya "kenapa 180?", jadi setiap angka butuh alasan.

### 4.2 Inventaris sumber log (cuplikan)

| Sumber | Aset in-scope | Dikirim ke | Format waktu | Pemilik | Terakhir diverifikasi |
|---|---|---|---|---|---|
| Firewall perimeter | fw-jkt1-01, fw-jkt1-02 | SIEM via syslog | UTC | Network Eng | 2026-09-30 |
| VPN appliance | vpn-jkt1-01 | SIEM via syslog | Waktu lokal (WIB), tanpa offset | Network Eng | 2026-09-30 |
| Hypervisor | hv-jkt1-01 sampai 08 | Wazuh agent | UTC | Platform | 2026-09-28 |
| AD/IdP | dc-01, dc-02 | Splunk UF | UTC | IT Ops | 2026-09-29 |

Baris VPN memakai waktu lokal tanpa offset zona, berbeda dari yang lain. Bila parser menganggapnya UTC, setiap event VPN tercatat 7 jam lebih maju dan korelasi login VPN dengan login AD meleset. Perbaikannya normalisasi di parser (misalnya `TZ` di `props.conf`) atau ubah konfigurasi perangkat.

### 4.3 Perintah cek sinkronisasi waktu (dijalankan di VM lab)

**Linux (systemd):**

```
timedatectl status
```

- **Tujuan:** melihat jam sistem, zona waktu, dan status sinkronisasi NTP.
- **Bagian penting:** `System clock synchronized` (status sinkron), `NTP service` (layanan aktif atau tidak), `Time zone`.
- **Keluaran ilustrasi:**

```
               Local time: Thu 2026-10-08 14:05:12 WIB
           Universal time: Thu 2026-10-08 07:05:12 UTC
                 RTC time: Thu 2026-10-08 07:05:12
                Time zone: Asia/Jakarta (WIB, +0700)
System clock synchronized: yes
              NTP service: active
          RTC in local TZ: no
```

- **Cara membaca:** Local time dan Universal time harus berselisih 7 jam untuk WIB.
- **Variasi:** bila VM memakai chrony, `chronyc tracking` menampilkan sumber acuan dan offset terakhir (baris `System time` dan `Last offset`), sedangkan `chronyc sources -v` menampilkan daftar server waktu; tanda `*` menandai sumber yang sedang dipakai.
- **Kapan gagal:** VM tanpa systemd tidak punya `timedatectl`; VM lab tanpa akses NTP menunjukkan `synchronized: no`, jadi jadikan satu VM server NTP internal lab.

**Windows:**

```
w32tm /query /status
```

- **Tujuan:** melihat sumber waktu dan sinkronisasi terakhir layanan Windows Time.
- **Bagian penting:** `Source` (sumber waktu) dan `Last Successful Sync Time`.
- **Cara membaca:** `Source` berisi `Local CMOS Clock` atau `Free-running System Clock` berarti mesin tidak sinkron ke sumber eksternal. Ini temuan 8.17.
- **Variasi:** `w32tm /query /peers` menampilkan daftar peer; di domain, klien biasanya sinkron ke domain controller. `w32tm /stripchart /computer:ntp1.lab.local /samples:5 /dataonly` mengukur offset terhadap server tertentu.
- **Kapan gagal:** layanan Windows Time tidak berjalan, atau prompt tanpa hak administrator.

### 4.4 Query Splunk untuk mendeteksi selisih waktu per host

```
index=* earliest=-24h latest=+1d
| eval lag_sec=_indextime-_time
| stats median(lag_sec) as median_lag min(lag_sec) as min_lag max(lag_sec) as max_lag count by host
| where abs(median_lag) > 60 OR min_lag < -5
| eval abs_median=abs(median_lag)
| sort - abs_median
| fields host median_lag min_lag max_lag count
```

- **Tujuan:** menemukan host yang jamnya kemungkinan tidak sinkron dengan membandingkan `_time` dan `_indextime`.
- **Penjelasan:**
  - `latest=+1d` wajib: bila hanya `earliest` yang ditulis, `latest` default ke saat ini, sehingga event bertimestamp masa depan tidak ikut terbaca.
  - `lag_sec` positif kecil itu normal (ada jeda kirim). Positif sangat besar berarti event tampak lebih tua dari sebenarnya, misalnya timestamp UTC dibaca sebagai WIB (sekitar +25200 detik) atau log lama yang dibaca ulang.
  - `lag_sec` negatif berarti event tampak terjadi setelah diindeks: jam host terlalu cepat, atau waktu lokal WIB dibaca sebagai UTC (sekitar -25200 detik).
  - `abs_median` menaruh selisih terbesar, ke arah mana pun, paling atas.
- **Keluaran ilustrasi:**

```
host          median_lag  min_lag  max_lag  count
vpn-jkt1-01       -25196   -25199   -25141    812
hv-jkt1-05           -42      -45       -3   4021
```

- **Cara membaca:** `vpn-jkt1-01` sekitar -25200 detik, cocok dengan waktu WIB tanpa offset di bagian 4.2. `hv-jkt1-05` punya lag negatif sekitar 42 detik, jadi jamnya kemungkinan maju sekitar 40 detik; cek NTP di host itu.
- **Variasi:** ganti `host` dengan `sourcetype`.
- **Kapan gagal:** `index=*` berat pada data besar, jadi batasi index. Dataset statis lama (misalnya BOTS) tidak bermakna karena waktu indeksnya jauh setelah waktu event; pakai data live dari VM lab.

### 4.5 Rekaman tinjauan log bulanan (bukti 8.15 dan 8.16)

```
REC-03 Tinjauan logging dan monitoring, September 2026 (peninjau: Lead SOC)
Cakupan sumber log in-scope : 49 dari 50 host mengirim log (98%); db-jkt1-03 berhenti sejak 2026-09-27 -> OPS-5530
Alert                       : 340 alert, 41 insiden (12%), 6 rule dituning (FP tinggi)
Waktu                       : vpn-jkt1-01 zona waktu salah (-25200 s) -> CA-2026-019;
                              hv-jkt1-05 maju sekitar 42 s, melebihi batas 1 s -> OPS-5521
Retensi                     : konfigurasi index dan ISM cocok dengan STD-LOG-01 (dicek 2026-09-30)
Akses admin SIEM            : 0 perubahan retensi tanpa tiket (audit trail ditinjau)
```

41 dari 340 sama dengan 12,06%, dibulatkan 12%. Rekaman ini sekaligus bukti 9.1 dan input management review.

## 5. Lab praktik (di VM lab terisolasi)

Simpan dokumen di `latihan/day11-<nama-org-fiktif>.md`. Jalankan perintah hanya di VM lab milikmu.

1. Tulis standar logging organisasi fiktifmu dengan format bagian 4.1. Setiap angka (retensi, selisih waktu) punya alasan tertulis.
2. Buat inventaris sumber log lab: setiap VM atau perangkat, tujuan log (Splunk atau Wazuh), format waktu, dan tanggal verifikasi.
3. Jalankan `timedatectl status` (Linux) dan `w32tm /query /status` (Windows) di VM lab. Tandai VM yang tidak sinkron.
4. Bila Splunk lab-mu punya data live, jalankan query bagian 4.4 dengan index yang kamu punya. Catat host dengan lag negatif atau median sangat besar.
5. Periksa retensi: `frozenTimePeriodInSecs` lewat `btool` di Splunk, atau kebijakan ISM di Wazuh. Bandingkan dengan standar logging-mu.
6. Periksa siapa yang bisa menghapus data atau mengubah retensi di SIEM lab. Catat sebagai bukti 8.15 atau temuan.
7. Tulis rekaman tinjauan bulanan seperti bagian 4.5 dari hasil langkah 2-6.
8. Tulis jawaban 2 menit untuk pertanyaan auditor: "Bagaimana kalian memastikan log yang relevan tersedia, terlindungi, ditinjau, dan waktunya konsisten?"

**Hasil yang sebaiknya tersimpan:**
- Standar logging, inventaris, dan rekaman tinjauan dari data lab-mu, dengan minimal satu temuan nyata (VM tidak sinkron, retensi tidak cocok, atau akses admin terlalu luas).
- Alasan untuk setiap angka di standar, dan angka rekaman tinjauan yang sudah dihitung ulang.
- Hasil cek waktu dari minimal satu VM Linux dan satu VM Windows, serta perbandingan retensi konfigurasi dengan standar.

**Variasi tantangan:** ambil snapshot, ubah zona waktu satu VM lab menjadi salah, kirim beberapa event, lalu tunjukkan bagaimana query bagian 4.4 menangkapnya. Kembalikan snapshot setelah selesai.

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Timeline insiden tidak masuk akal (respons sebelum serangan) | Zona waktu salah tafsir atau jam host tidak sinkron | Query lag bagian 4.4; cek `timedatectl` atau `w32tm` di host |
| Event satu sumber tidak muncul di search 24 jam terakhir | Timestamp masa depan dan `latest` default ke saat ini | Tambah `latest=+1d`; perbaiki zona waktu sumber |
| Retensi standar berbeda dengan konfigurasi | Standar ditulis tanpa melihat konfigurasi | Tinjau keduanya setiap kuartal |
| Admin bisa menghapus log tanpa jejak | Role SIEM terlalu luas | Pisahkan peran; kirim audit trail ke penyimpanan terpisah |
| Banyak alert tetapi tidak ada insiden tercatat | Alert tidak terhubung ke proses 5.25 | Alert prioritas tinggi wajib punya tiket dan keputusan |

## 7. Kesalahan umum dan jebakan

- Mengumpulkan log tanpa pernah meninjaunya. Itu memenuhi sebagian 8.15, tetapi tidak 8.16.
- Lupa bahwa SIEM sendiri sistem in-scope: aktivitas admin SIEM harus dicatat dan dilindungi.
- Menyimpan data pribadi di log tanpa masking atau batas akses, sehingga 8.11 dan UU PDP ikut terdampak.
- `[komunitas]` Pengguna Splunk sering kaget karena data bertahan lebih lama dari `frozenTimePeriodInSecs`, karena bucket baru digulung saat event terbarunya melewati batas [S6].

## 8. Catatan terkini

- Best Practices for Event Logging and Threat Detection dari ASD's ACSC, CISA, FBI, NSA, dan mitra internasional terbit 21 Agustus 2024 [S1] dan masih menjadi panduan logging lintas negara yang paling sering dirujuk.
- NIST SP 800-92 Rev. 1 masih berstatus initial public draft (Oktober 2023) per Oktober 2026 [S3].
- Dokumentasi Wazuh 4.14 (rilis terbaru 4.14.8) menempatkan retensi index di Index State Management dengan contoh 90 hari [S5]. Cek ulang menu bila lab-mu memakai versi lain.

## 9. Cheat sheet

```
8.15 Logging  : catat (siapa, apa, kapan, di mana, hasil) | simpan | lindungi (integritas, admin, kerahasiaan) | analisis
                gabungan A.12.4.1-A.12.4.3 (2013)
8.16 Monitoring: pantau + baseline normal + cari anomali -> 5.25 nilai -> 5.26 respons ; bukti: rule, tiket, tuning (kontrol baru 2022)
8.17 Waktu    : sumber acuan disetujui, NTP/PTP, pertimbangkan 2 sumber, catat beda cloud ; simpan UTC (eks A.12.4.4)
Pendukung     : 5.33 records | 8.10 deletion | 8.11 masking | 8.2 privileged | 5.3 SoD
Retensi       : tidak ada angka di standar; dasar = hukum/kontrak + investigasi + biaya + privasi
  Splunk: frozenTimePeriodInSecs (default 188697600 s = 2184 hari = 6 x 364) ; splunk btool indexes list <idx> --debug
  Wazuh 4.14: ISM policy (Indexer management > Index Management > State management policies), min_index_age
ASD/CISA 2024: kebijakan logging | terpusat + korelasi | penyimpanan aman + integritas | strategi deteksi
Cek waktu: timedatectl status | chronyc tracking | chronyc sources -v | w32tm /query /status | w32tm /stripchart
Splunk lag: eval lag_sec=_indextime-_time ; pakai latest=+1d
  ~ -25200 = WIB dibaca sebagai UTC ; ~ +25200 = UTC dibaca sebagai WIB ; negatif kecil = jam host maju
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | CISA: ASD's ACSC, CISA, FBI, and NSA release Best Practices for Event Logging and Threat Detection | https://cisa.gov/news-events/alerts/2024/08/21/asds-acsc-cisa-fbi-and-nsa-support-international-partners-release-best-practices-event-logging-and | primer (lembaga pemerintah) | 2024-08-21; diakses 2026-10-08 | Tinggi untuk fakta rilis dan cakupan |
| S2 | ASD's ACSC: Best practices for event logging and threat detection | https://www.cyber.gov.au/business-government/detecting-responding-to-threats/event-logging/best-practices-event-logging-threat-detection | primer (lembaga pemerintah) | 2024; diakses 2026-10-08 | Sedang-tinggi. Empat pertimbangan, sumber waktu, retensi |
| S3 | NIST CSRC: SP 800-92 Rev. 1 (initial public draft) | https://csrc.nist.gov/pubs/sp/800/92/r1/ipd | primer (NIST) | 2023-10-11; diakses 2026-10-10 | Tinggi untuk tanggal dan status draft |
| S4 | ISMS.online: ISO 27002 control 8.16 monitoring activities | https://www.isms.online/iso-27002/control-8-16-monitoring-activities/ | sekunder (vendor) | 2025-07-25; diakses 2026-10-08 | Sedang. Ringkasan panduan 8.16 |
| S5 | Wazuh documentation 4.14: Index lifecycle management | https://documentation.wazuh.com/4.14/user-manual/wazuh-indexer-cluster/index-lifecycle-management.html | primer (dokumentasi resmi) | versi 4.14; diakses 2026-10-10 | Tinggi. Menu dan contoh kebijakan retensi |
| S6 | Splunk Community: Why is frozenTimePeriodInSecs 188697600? | https://community.splunk.com/t5/Getting-Data-In/Why-is-frozenTimePeriodInSecs-188697600/td-p/160360 | komunitas | diakses 2026-10-08 | Sedang. Nilai default dan perilaku bucket; nilai default juga tercantum di spesifikasi indexes.conf |
| S7 | Bemopro: ISO 27001 audit logging requirements | https://www.bemopro.com/compliance-requirements/iso-27001-audit-logging | sekunder (vendor) | diakses 2026-10-08 | Rendah-sedang. Contoh interpretasi berlebihan (SIEM real-time, UEBA) |
| S8 | ISMS.online: ISO 27002 control 8.17 clock synchronisation | https://www.isms.online/iso-27002/control-8-17-clock-synchronisation | sekunder (vendor) | 2025-07-25; diakses 2026-10-10 | Sedang. Sumber acuan, NTP/PTP, dua sumber, cloud |
| S9 | ISMS.online: ISO 27002 control 8.15 logging | https://www.isms.online/iso-27002/control-8-15-logging/ | sekunder (vendor) | 2025-07-25; diakses 2026-10-10 | Sedang. Isi entri log, daftar event, proteksi, masking saat berbagi log |

**Catatan sumber:** panduan 8.15-8.17 dirangkum dari ringkasan vendor atas 27002. Nilai default `frozenTimePeriodInSecs` bersumber dari diskusi komunitas yang mengutip spesifikasi `indexes.conf`; cek dengan `btool` di instance Splunk 10.6 lab-mu.
