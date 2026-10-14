---
day: 21
title: 'Defenses dan sumber data: sistem pertahanan, alat analisis, dan sumber data paling berguna untuk analisis ancaman'
researched_on: 2026-10-07
versions_checked: MITRE ATT&CK v19.2 (Agu 2026; v18 Okt 2025 mengganti Data Sources dengan Detection Strategies/Analytics); ASD ACSC/CISA dkk. "Best Practices for Event Logging and Threat Detection" (21 Agu 2024); Sysmon (halaman Microsoft Learn 10 Sep 2026; Windows 11+/Server 2019+); Splunk CIM 6.4 (4 Feb 2026); Splunk Enterprise 10.6
---

# Day 21: Defenses dan sumber data

Cakupan: mengidentifikasi jenis sistem pertahanan siber, alat analisis, dan sumber data yang paling berguna untuk analisis ancaman.

## Ide inti

Detection, hunting, dan investigasi hanya sebaik data yang masuk, jadi pertanyaan pertama sebelum membahas data model dan normalisasi adalah pertanyaan yang jauh lebih sederhana: apa yang sebenarnya bisa kita lihat? Day 03 sampai 06 membahas isi masing-masing sumber log satu per satu, mulai dari Windows Security dan Sysmon sampai log jaringan, Linux, dan identitas cloud. Day ini memundurkan sudut pandang satu langkah: mengelompokkan sistem pertahanan menurut lapisan yang dijaganya, mengenali data yang dihasilkan setiap lapisan, lalu memilih sumber berdasarkan pertanyaan analisis yang mau dijawab, bukan berdasarkan daftar produk yang sudah dibeli. Dari situ muncul dua pekerjaan yang bisa dikerjakan dengan SPL biasa, yaitu membuat inventaris sumber data beserta kesegarannya dan memetakan sourcetype ke data model, dan keduanya menjadi pintu masuk ke pembahasan CIM di Day berikutnya.

Analoginya adalah titik monitoring di jaringan. Gangguan hanya terlihat di segmen yang benar-benar dipantau, dan POP tanpa titik ukur akan diam saja sampai pelanggan menelepon. Batas analoginya ada di langkah setelah data masuk: di NMS, perangkat yang sudah terpantau langsung muncul di grafik, sedangkan di SIEM sumber yang sudah masuk index belum tentu terpakai, karena tanpa tag dan field yang benar data bervolume besar tetap tidak muncul di data model dan detection yang bergantung pada model itu tidak akan pernah fire. Kesegaran data punya analogi yang sama tajamnya: polling yang berhenti memberi grafik rata, dan grafik rata mudah disalahartikan sebagai jaringan yang tenang. Sumber log yang mendadak diam juga bukan sekadar masalah operasional, karena salah satu penyebabnya adalah agent yang dimatikan penyerang.

**Kapan relevan:** menilai cakupan visibilitas sebelum menjanjikan sebuah detection, menjelaskan kenapa satu pertanyaan investigasi tidak bisa dijawab dengan data yang ada, menyusun usulan sumber data berikutnya beserta alasannya, dan membenarkan biaya ingest ke pihak yang membayarnya.
**Kapan bukan jawaban:** daftar sumber yang panjang bukan bukti kemampuan deteksi. Sumber yang masuk tanpa normalisasi tetap tidak terbaca data model (Day 23), dan menambah sumber tanpa use case justru menaikkan biaya sekaligus menenggelamkan sinyal [S6]. Inventaris juga bukan pengganti perbaikan di sisi sumbernya: kalau command line tidak terekam karena audit policy atau konfigurasi Sysmon tidak mengaktifkan event yang kamu butuhkan, yang harus diubah adalah konfigurasi di host, bukan query di Splunk.

## 1. Konsep inti

### 1.1 Sistem pertahanan menurut lapisan

| Lapisan | Contoh sistem | Fungsi utama | Data yang dihasilkan untuk SIEM |
|---|---|---|---|
| Perimeter/jaringan | Firewall/NGFW, IDS/IPS, WAF, VPN | Mencegah dan mendeteksi trafik | Allow/deny, alert signature, sesi VPN |
| Web dan email | Secure web gateway/proxy, email security gateway | Menyaring URL/lampiran/phishing | URL, user, kategori, verdict; pengirim, lampiran, verdict |
| DNS | Resolver internal, DNS security | Resolusi nama, blokir domain | Query/response per host |
| Endpoint | AV/EPP, EDR, HIDS (mis. Wazuh), Sysmon | Mencegah, mendeteksi, dan merespons di host | Proses, file, registry, koneksi, alert |
| Identitas | AD/DC, IdP/SSO, MFA, PAM | Autentikasi dan otorisasi | Logon sukses/gagal, MFA, perubahan grup |
| Cloud | Audit log cloud (mis. AWS CloudTrail, Azure Activity/Entra), CSPM, CASB | Kontrol dan visibilitas layanan cloud | API call, sign-in, konfigurasi berisiko |
| Data | DLP, database activity monitoring | Mencegah kebocoran data | Pelanggaran kebijakan, akses data sensitif |
| Kerentanan | Vulnerability scanner | Menemukan kelemahan | Daftar kerentanan per aset |

Prinsip defense in depth: tidak ada satu lapisan yang cukup. SIEM bernilai karena mengorelasikan jejak dari banyak lapisan atas kejadian yang sama.

### 1.2 Alat analisis

| Alat | Peran | Hubungan dengan Splunk |
|---|---|---|
| SIEM | Mengumpulkan, menormalkan, mengorelasikan log; deteksi dan investigasi | Splunk Enterprise + ES |
| SOAR | Orkestrasi dan otomasi respons (playbook) | Splunk SOAR (Day 42) |
| UEBA | Analitik perilaku user/entitas, anomali | Fitur/produk perilaku Splunk, cek penamaan produk terkini; RBA di ES adalah pendekatan yang berbeda (Day 35) |
| EDR / XDR | Telemetri dan respons endpoint; XDR memperluas ke banyak domain | Sumber data penting bagi SIEM |
| NDR | Deteksi berbasis trafik jaringan | Sumber data (alert + metadata) |
| TIP | Platform intelijen ancaman | Threat list/intel di ES (Day 30) |
| Sandbox | Detonasi file/URL untuk verdict | Hasil diperkaya ke investigasi |
| Vulnerability scanner | Kelemahan per aset | Konteks prioritas (CIM Vulnerabilities) |

Batas antar kategori kabur dan sarat pemasaran (mis. XDR vs SIEM). Pegang fungsinya, bukan nama produknya.

### 1.3 Sumber data paling berguna: mulai dari pertanyaan

Panduan bersama ASD ACSC, CISA, FBI, NSA, dan mitra internasional (Agustus 2024) menekankan empat faktor [S1][S2]:
1. Kebijakan event logging yang disetujui perusahaan.
2. Akses log terpusat dan korelasi.
3. Penyimpanan yang aman serta integritas log.
4. Strategi deteksi untuk ancaman yang relevan, termasuk teknik living off the land (penyerang memakai alat bawaan sistem).

Prioritas sumber log dalam panduan itu: sistem kritis dan data yang paling mungkin diincar, layanan yang menghadap internet, platform identitas dan domain, EDR, lingkungan cloud, OT, dan infrastruktur jaringan [S1][S2]. Panduan ini juga menuntut format terstruktur dan konsisten serta timestamp tepercaya: UTC, ISO 8601, sumber waktu tersinkron [S2].

Pandangan praktisi yang sejalan: SIEM sebaiknya digerakkan output. Sumber data dipilih berdasarkan use case dan risiko, bukan "kumpulkan semua". Volume terbesar sering membawa sinyal keamanan terkecil (pola 80/20) [S6]. `[sekunder]`

Tabel praktis "pertanyaan, sumber terbaik, data model CIM" (nama data model, cek di CIM 6.4, Day 23):

| Pertanyaan analisis | Sumber terbaik | Data model CIM |
|---|---|---|
| Siapa login ke mana, dari mana, berhasil/gagal? | DC/AD, IdP/SSO, VPN, Linux auth | Authentication |
| Proses apa berjalan, dengan command line apa, diluncurkan oleh siapa? | EDR, Sysmon EID 1, Windows 4688 + command line | Endpoint (Processes) |
| Perubahan persistence (service, task, registry)? | Sysmon 12/13, EDR, Windows 7045/4698, perlu dicek | Endpoint (Services, Registry), Change |
| Host berbicara dengan siapa? | Firewall, NetFlow, Zeek conn, Sysmon EID 3 | Network_Traffic |
| Domain apa yang di-resolve? | Resolver DNS, Sysmon EID 22, Zeek dns | Network_Resolution |
| URL apa yang diakses, oleh siapa? | Proxy/SWG, WAF, web server | Web |
| Email apa yang masuk/keluar, lampiran apa? | Email gateway, M365/Google audit | Email |
| Signature apa yang terpicu? | IDS/IPS, NDR | Intrusion_Detection |
| Malware terdeteksi di mana? | AV/EPP/EDR | Malware |
| Siapa mengubah konfigurasi/akun? | AD changes, cloud audit, perangkat jaringan | Change |
| Aset mana yang rentan? | Vulnerability scanner | Vulnerabilities |

Sysmon layak disebut khusus karena gratis dan sangat informatif untuk Windows [S4]:
- EID 1 process creation dengan command line penuh, hash, dan `ProcessGuid` (korelasi meski PID dipakai ulang).
- EID 3 network connection (nonaktif secara default).
- EID 7 image load (default nonaktif, berisik).
- EID 8 CreateRemoteThread, EID 10 ProcessAccess (mis. akses ke LSASS).
- EID 11 FileCreate, EID 12-14 registry, EID 22 DNS query.
- EID 23/26 file delete, EID 25 process tampering, EID 27-29 blokir/deteksi executable.

Event ditulis ke log `Microsoft-Windows-Sysmon/Operational` dengan timestamp UTC. Halaman terbaru menyebut Sysmon berjalan di Windows 11+ dan Server 2019+ [S4]. Sysmon tidak menganalisis apa pun dan tidak menyembunyikan diri. Analisis terjadi di SIEM [S4].

### 1.4 ATT&CK dan sumber data: perubahan penting

Dulu ATT&CK memetakan teknik ke Data Sources/Data Components. Sejak v18 (28 Okt 2025), Data Sources dipensiunkan dan diganti Detection Strategies (DETxxxx) dan Analytics (ANxxxx) untuk setiap teknik. Analytics menunjuk log source dan data component yang relevan [S3]. Versi ATT&CK saat ini adalah v19.2 (Agustus 2026; v19 dirilis April 2026). v19.2 adalah rilis "Agile" pertama yang memperbarui Groups/Software/Campaigns di luar jadwal dua kali setahun [S5].

Implikasinya: materi lama yang menyebut "ATT&CK data sources" masih relevan secara konsep. Saat mencari di attack.mitre.org sekarang, kamu akan melihat Detection Strategies dan Analytics. Cek tampilan halaman teknik di v19.

### 1.5 Enterprise vs ES

- Ingest, normalisasi CIM, dan inventaris data bisa dilakukan di Splunk Enterprise + add-on CIM + TA vendor.
- ES menambahkan cara menilai cakupan sumber data, mis. dashboard audit data model dan konten yang memeriksa sumber data (Day 27), serta memakai data itu untuk detection, risk, dan aset/identitas.

## 2. Contoh SPL dan langkah di ES

> Keluaran berlabel ilustrasi.

### 2.1 Inventaris sumber data dan kesegaran (freshness)

```
| tstats count latest(_time) AS last_event where index=* by index sourcetype
| eval lag_min=round((now()-last_event)/60, 0)
| eval status=case(lag_min<=15, "fresh", lag_min<=1440, "delayed", true(), "stale")
| convert ctime(last_event)
| sort index sourcetype
```

- `tstats ... where index=*`: di `tstats`, ini relatif murah karena hanya membaca metadata tsidx (Day 25). Di raw search, `index=*` tetap harus dihindari (Day 14).
- `lag_min`: berapa menit sejak event terakhir. Sumber yang "diam" adalah celah visibilitas yang sering tidak disadari.
- Ambang 15 menit/1 hari adalah asumsi. Sesuaikan dengan pola tiap sumber.
- Cek hak akses ke `index=*` dan index internal tergantung peran user-mu.

Keluaran ilustrasi:

```
index     sourcetype                         count     last_event            lag_min  status
wineventlog XmlWinEventLog:Security          2.1 jt    10/07/2026 17:41:02   2        fresh
proxy     bluecoat:proxysg:access            0.9 jt    10/06/2026 03:10:55   2310     stale
```

**Cara membaca hasil:** proxy yang "stale" berarti investigasi web selama sekitar 38 jam terakhir buta. Itu temuan, bukan sekadar masalah teknis.

### 2.2 Peta sourcetype ke data model

```
| tstats count from datamodel=Authentication by sourcetype
| eval datamodel="Authentication"
| append [| tstats count from datamodel=Endpoint.Processes by sourcetype | eval datamodel="Endpoint.Processes"]
| append [| tstats count from datamodel=Network_Traffic by sourcetype | eval datamodel="Network_Traffic"]
| append [| tstats count from datamodel=Network_Resolution by sourcetype | eval datamodel="Network_Resolution"]
| append [| tstats count from datamodel=Web by sourcetype | eval datamodel="Web"]
| table datamodel sourcetype count
```

- `append` + subsearch `tstats` per data model. Jumlah data model sedikit, jadi batas subsearch tidak masalah.
- Hasilnya adalah matriks cakupan: data model yang kosong berarti detection berbasis model itu tidak akan pernah fire (Day 45).
- Tanpa akselerasi, `tstats` dari data model tetap jalan (lebih lambat) karena `summariesonly` default false (Day 25).

### 2.3 Profil cepat satu sumber: Sysmon

```
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" earliest=-24h
| stats count BY EventCode host
| xyseries host EventCode count
```

- Menunjukkan event ID Sysmon apa yang benar-benar dikumpulkan per host.
- **Cara membaca hasil:** jika EID 3, 10, atau 22 tidak ada, kemungkinan konfigurasi Sysmon tidak mengaktifkannya. Ingat, EID 3 default nonaktif [S4]. Detection yang bergantung pada event itu akan buta.
- Di lab, ganti `index=*` dengan index Sysmon-mu (efisiensi, Day 14).

### 2.4 Metadata cepat

```
| metadata type=sourcetypes index=botsv1
| eval first=strftime(firstTime,"%F %T"), last=strftime(lastTime,"%F %T")
| table sourcetype totalCount first last
```

- `metadata` adalah generating command yang membaca metadata index (cepat), cek field `firstTime`/`lastTime`/`totalCount` di versi-mu.

### 2.5 Di ES (generik)

- Gunakan dashboard audit data model/akselerasi (Day 25, Data Model Audit) dan halaman aset/identitas untuk memastikan sumber identitas dan aset terisi (Day 26).
- Hubungkan inventaris sumber data dengan konten: SSE dan ES dapat menilai sumber data dan menyarankan konten (Day 27).

## 3. Lab praktik

1. Jalankan bagian 2.1 di Splunk lab. Daftarkan setiap sumber dengan statusnya.
2. Jalankan bagian 2.2. Buat matriks data model x sourcetype.
3. Isi tabel bagian 1.3 untuk lab-mu: kolom "ada / tidak / sebagian". Contoh: Authentication ada (Windows Security), Web tidak ada (belum ada proxy).
4. Periksa konfigurasi Sysmon di VM Windows (`sysmon -c` untuk dump konfigurasi [S4]) dan jalankan bagian 2.3. Catat event ID yang aktif.
5. Pilih 3 teknik ATT&CK yang relevan untuk lab (mis. scheduled task, PowerShell, credential dumping). Untuk masing-masing, buka halaman teknik di attack.mitre.org v19, baca Detection Strategy/Analytics, lalu tentukan apakah data lab-mu memadai.
6. Tulis rekomendasi "3 sumber data berikutnya" untuk lab, dengan alasan berbasis tabel bagian 1.3 dan panduan ASD/CISA [S2].

**Hasil yang sebaiknya tersimpan:**
- Inventaris dengan status fresh/delayed/stale.
- Matriks data model x sourcetype.
- Daftar event ID Sysmon aktif per host.
- Analisis 3 teknik ATT&CK vs data lab.
- Rekomendasi 3 sumber data berikutnya.

**Variasi tantangan:** buat alert terjadwal sederhana yang memicu bila sourcetype penting (Security, Sysmon) tidak mengirim data lebih dari 60 menit. Jelaskan kenapa "data berhenti" adalah sinyal keamanan juga (mis. agent dimatikan penyerang).

## 4. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Sourcetype ada, tapi data model kosong | TA tidak memetakan ke CIM (tag/field) | Cek tag `eventtype`/`tag`; pasang TA yang benar (Day 23) |
| Lag besar untuk satu sumber | Forwarder mati, antrean, jam host salah | Cek `_internal` forwarder; cek NTP; bandingkan `_indextime` vs `_time`, perlu dicek |
| Sysmon EID 3/22 tidak ada | Tidak diaktifkan di konfigurasi | Perbarui konfigurasi (`sysmon -c config.xml`) [S4] |
| `_time` meleset jam-an | Zona waktu/parsing timestamp | Normalisasi UTC; perbaiki `TZ` di props (admin) [S2] |
| Volume ingest membengkak tanpa nilai | Sumber berisik dengan sinyal rendah | Filter di sumber; prioritas berbasis use case [S6] |

## 5. Kesalahan umum dan jebakan

- "Kumpulkan semua" tanpa use case. Mahal dan menenggelamkan sinyal [S6].
- Tidak memantau kesegaran data. Detection "hijau" di atas data yang berhenti mengalir.
- Menganggap EDR menggantikan log identitas/jaringan. Pertanyaan berbeda butuh sumber berbeda.
- Mengabaikan timestamp dan zona waktu. Korelasi lintas sumber gagal [S2].
- Memakai istilah ATT&CK "data sources" tanpa sadar perubahan v18 [S3].
- Pandangan "output-driven SIEM" dan pola 80/20 berasal dari blog praktisi [S6]. Arah umumnya sejalan dengan panduan pemerintah [S2], tetapi angka 80/20 adalah heuristik, bukan hasil pengukuran.

## 6. Catatan terkini

- **ATT&CK v18 (Okt 2025):** Data Sources dipensiunkan, diganti Detection Strategies + Analytics [S3]. v19 (Apr 2026) dan v19.2 (Agu 2026, rilis Agile pertama) [S5].
- Panduan logging ASD/CISA (Agu 2024) masih menjadi rujukan utama lintas negara untuk prioritas log [S1][S2].
- Sysmon (halaman diperbarui 10 Sep 2026) mencantumkan event hingga EID 29 (FileExecutableDetected) dan dukungan Windows 11+/Server 2019+ [S4].
- CIM 6.4.0 (4 Feb 2026) menambah field unit bisnis di data model Data Access untuk aset/identitas, plus beberapa field di Network Sessions, Network Traffic, dan Endpoint [S7].

## 7. Cheat sheet

```
LAPISAN   network(FW/IDS/IPS/WAF/VPN) | web/email(proxy, mail GW) | DNS | endpoint(EPP/EDR/HIDS/Sysmon)
          | identity(AD/IdP/MFA/PAM) | cloud(audit logs, CSPM/CASB) | data(DLP) | vuln scanner
ANALISIS  SIEM (korelasi) | SOAR (otomasi) | UEBA (perilaku) | EDR/XDR | NDR | TIP | sandbox
PRIORITAS (ASD/CISA 2024) kritis & data incaran -> internet-facing -> identitas/DC -> EDR -> cloud -> OT -> jaringan
          + format terstruktur + UTC/ISO8601 + retensi + terpusat + strategi deteksi (LOTL)
PERTANYAAN -> DM: login=Authentication | proses=Endpoint | koneksi=Network_Traffic | DNS=Network_Resolution
          | URL=Web | email=Email | signature=Intrusion_Detection | malware=Malware | perubahan=Change | vuln=Vulnerabilities
SYSMON    1 proc | 3 net(off default) | 7 image | 8 remote thread | 10 proc access | 11 file | 12-14 reg | 22 DNS | 23/26 delete | 25 tamper
ATT&CK    v18: data sources -> Detection Strategies + Analytics ; kini v19.2
INVENTARIS | tstats count latest(_time) where index=* by index sourcetype -> lag
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Sysmon sudah terpasang dan volumenya paling besar di antara semua sourcetype, jadi detection berbasis data model Endpoint sudah pasti bekerja." Apa dua hal yang masih bisa membuat kalimat ini salah?

<details><summary>Jawaban</summary>

Pertama, volume bukan jaminan normalisasi. Sourcetype bisa penuh event tetapi data model tetap kosong bila add-on tidak memetakan field dan tag yang dibutuhkan, dan detection yang membaca data model itu tidak akan pernah fire. Cara memeriksanya adalah menghitung dari data model, bukan dari index, seperti pada peta sourcetype ke data model. Kedua, Sysmon hanya mencatat apa yang dinyalakan di konfigurasinya: event network connection tidak aktif secara default, dan event seperti process access ke LSASS atau DNS query bisa tidak ada sama sekali, sehingga profil per host perlu diperiksa sebelum detection dijanjikan. Lihat bagian 1.3, 2.2, 2.3, dan 4.

</details>

**2. Skenario keputusan.** Inventaris sumber datamu menunjukkan sourcetype proxy berstatus stale, dengan event terakhir sekitar 38 jam lalu. Apa langkah yang paling tepat?

- A. Serahkan ke tim infrastruktur sebagai masalah teknis forwarder, lalu lanjutkan triage seperti biasa.
- B. Catat sebagai temuan visibilitas: beri tahu pemilik sumber, tandai rentang 38 jam itu sebagai periode buta untuk investigasi web, lalu buat alert bila sumber penting berhenti mengirim data.
- C. Ganti pertanyaan investigasi web ke log firewall, karena keduanya sama-sama log jaringan.

<details><summary>Jawaban</summary>

B. Sumber yang diam berarti setiap pertanyaan tentang akses web selama 38 jam itu tidak bisa dijawab, dan kesimpulan "tidak ada bukti akses ke domain itu" menjadi tidak sah untuk rentang tersebut. Karena itu statusnya temuan, bukan sekadar tiket operasional, dan tindak lanjut yang masuk akal adalah alert sederhana yang memicu bila sourcetype penting tidak mengirim data lebih dari satu jam. A tidak salah sebagai langkah operasional, tetapi membiarkan triage berjalan seolah datanya lengkap. C menukar pertanyaan dengan pertanyaan lain: firewall menjawab siapa berbicara dengan siapa, sedangkan URL, user, dan kategori hanya ada di log proxy. Lihat bagian 1.3, 2.1, 3, dan 4.

</details>

**3. Pertanyaan jebakan.** Kamu membuka halaman sebuah teknik di attack.mitre.org untuk melihat daftar Data Sources seperti yang kamu ingat, tetapi tidak menemukannya. Apa yang terjadi, dan apakah materi lama yang menyebut "ATT&CK data sources" otomatis jadi salah?

<details><summary>Jawaban</summary>

Sejak ATT&CK v18 (Oktober 2025) Data Sources dipensiunkan dan diganti Detection Strategies serta Analytics per teknik, dan Analytics itulah yang sekarang menunjuk log source dan data component yang relevan. Versi saat ini v19.2 (Agustus 2026). Materi lama tidak menjadi salah secara konsep, karena gagasannya tetap sama yaitu memetakan teknik ke data yang bisa membuktikannya; yang berubah adalah nama dan tempatnya di halaman teknik. Yang perlu dijaga adalah kosakata saat berbicara dengan orang lain, supaya diskusi cakupan tidak memakai istilah yang sudah tidak ada di sumbernya. Lihat bagian 1.4 dan 6.

</details>

**4. Jelaskan ulang.** Jelaskan ke SOC lead, dalam tiga kalimat, kenapa menambah dua sumber log baru belum tentu menambah kemampuan deteksi.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh jawaban: "Sumber baru hanya menambah kemampuan kalau ada pertanyaan analisis yang sebelumnya tidak bisa kita jawab, misalnya kita belum punya jawaban untuk URL apa yang diakses siapa, atau proses apa berjalan dengan command line apa. Setelah masuk, sumber itu masih harus dinormalisasi ke field dan tag yang benar supaya terbaca data model, dipantau kesegarannya, dan punya konten yang memakainya; tanpa itu dia hanya menambah biaya ingest. Jadi urutannya pertanyaan dulu, lalu sumber, lalu normalisasi dan konten, dan sumber bervolume terbesar sering justru bukan yang paling banyak membawa sinyal keamanan."

Kesalahan yang sering muncul: menjawab dengan jumlah sumber atau volume ingest sebagai ukuran kemajuan; mengira EDR bisa menggantikan log identitas dan jaringan padahal pertanyaannya berbeda; dan melewatkan kesegaran data, sehingga detection terlihat sehat di atas sumber yang sudah berhenti mengalir. Lihat bagian 1.3, 2.1, dan 5.

</details>

**5. Interview question (English).** "You are building out visibility for a SOC. How do you decide which log sources to onboard first?"

<details><summary>Sample answer</summary>

"I start from the questions the SOC has to answer during triage, not from the product list: who logged in from where and whether it succeeded, what process ran with what command line, who a host talked to, what domains it resolved, what URLs a user opened, and who changed an account or a configuration. Each of those maps to a source and to a CIM data model, so the gaps become concrete instead of a feeling. I then weight them the way the joint ASD and CISA logging guidance does: critical systems and the data most likely to be targeted, internet-facing services, identity and domain platforms, EDR, cloud, OT, and network infrastructure, and I insist on consistent structured formats with trustworthy synchronised timestamps in UTC, because without that cross-source correlation quietly fails. Onboarding is not finished when data arrives: it has to be normalised so the data models actually populate, monitored for freshness, and tied to content that uses it, otherwise I have added cost rather than coverage. And I treat volume with suspicion, since the noisiest source is often the one carrying the least security signal."

What makes this answer strong: it drives source selection from analytical questions and names the data models they land in, cites the published prioritisation rather than personal preference, and treats normalisation, freshness and content as part of onboarding instead of afterthoughts.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | CISA alert: ASD's ACSC, CISA, FBI, NSA, and international partners release Best Practices for Event Logging and Threat Detection | https://cisa.gov/news-events/alerts/2024/08/21/asds-acsc-cisa-fbi-and-nsa-support-international-partners-release-best-practices-event-logging-and | primer | 2024-08-21 | Tinggi |
| S2 | CISA: Best Practices for Event Logging and Threat Detection (halaman sumber daya) | https://cisa.gov/resources-tools/resources/best-practices-event-logging-and-threat-detection | primer | 2024-08-21; diakses 2026-10-07 | Tinggi. Ringkasan halaman sumber daya; rincian per jenis log ada di PDF panduan |
| S3 | ATT&CK Updates: October 2025 (v18); ringkasan Picus "What's new in ATT&CK v18" | https://attack.mitre.org/resources/updates/updates-october-2025/ | primer | 2025-10-28 | Tinggi untuk fakta perubahan |
| S4 | Microsoft Learn: Sysmon (Sysinternals) | https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon | primer | 2026-09-10; diakses 2026-10-07 | Tinggi. Event ID, konfigurasi, OS |
| S5 | MITRE ATT&CK: Updates (indeks rilis) | https://attack.mitre.org/resources/updates/ | primer | diakses 2026-10-07 | Tinggi. v19.2 sebagai versi saat ini |
| S6 | Security Boulevard (Anton Chuvakin): One more time on SIEM telemetry/log sources; ringkasan praktisi 80/20 | https://securityboulevard.com/2024/03/one-more-time-on-siem-telemetry-log-sources/ | sekunder (praktisi) | 2024-03 | Sedang |
| S7 | Release notes Splunk CIM Add-on 6.4 | https://help.splunk.com/en/data-management/common-information-model/6.4/introduction/release-notes-for-the-splunk-common-information-model-add-on | primer | 2026-02-04 | Tinggi |

**Catatan sumber:** ringkasan panduan ASD/CISA di Day ini diambil dari halaman sumber daya [S1][S2]; rincian rekomendasi per jenis log ada di PDF panduannya. LOTL di sini berarti teknik penyerang yang memakai alat bawaan sistem, bukan alat bawaan untuk deteksi. Daftar data model CIM dibahas dan bersumber di Day 23. Nama produk UEBA Splunk saat ini perlu dicek di halaman produk Splunk.
