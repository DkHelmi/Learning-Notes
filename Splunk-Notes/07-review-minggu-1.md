---
day: 07
title: 'Review Minggu 1: command SPL dan search efisien, mini-lab gabungan di BOTS v1'
researched_on: 2026-10-10
versions_checked: Splunk Enterprise 10.6 (dokumentasi 10.x); dataset BOTS v1 (repo splunk/botsv1; index botsv1; lisensi CC0); ES 8.7 (istilah)
---

# Day 07: Review Minggu 1 (command SPL dan search efisien)

Cakupan: mengikat kembali command SPL inti dan praktik search efisien dari Day 01-06 lewat ringkasan per topik, peta konsep, glosarium, dan satu lab gabungan.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- menjelaskan setiap command SPL inti (`tstats`, `transaction`, `rex`, `eval`, `foreach`, `lookup`, `makeresults`) dalam satu kalimat, dan kapan memakainya untuk keamanan.
- menerapkan prinsip search efisien (bagian 3.2) pada investigasi nyata dan mengukurnya.
- menunjuk sumber konten SPL yang tepat (bagian 3.3) untuk sebuah kebutuhan.
- menjawab skenario singkat yang menuntut pilihan command dan menjelaskan alasannya (bagian 3d).
- menjalankan investigasi berlapis di BOTS v1 yang menggabungkan `tstats`, `stats`/`transaction`, `rex`/`eval`, `lookup`, dan `makeresults`.

## 2. Konteks singkat

Day 01-06 membahas command SPL satu per satu. Review ini melatih kemampuan menggabungkannya, karena investigasi nyata jarang memakai satu command saja.

Dataset latihan: BOTS v1 dari Splunk, dirilis 2016 dengan lisensi CC0. Datanya ada di `index=botsv1` dan berisi 21 sourcetype (Windows event log, Sysmon, Fortigate, IIS, Nessus, Stream (DNS/HTTP/SMB, dll.), Suricata, registry Windows). Dataset ini membutuhkan add-on terkait, termasuk TA Windows, Sysmon, Stream, Suricata, dan URL Toolbox [S1]. Tersedia versi penuh (sekitar 6,1 GB terkompresi) dan versi "attack only" (sekitar 135 MB) [S1]. BOTS v1 memuat dua skenario: defacement website fiktif `imreallynotbatman.com` dan ransomware pada workstation `we8105desk` [S2].

> Catatan: dataset ini juga dipakai sebagai CTF. Lab di bawah memakai metode tanpa menyebut jawaban spesifik. Jangan mencari kunci jawaban; tujuan latihannya adalah prosesnya.

## 3. Ringkasan per topik

### 3.1 Command SPL untuk analisis keamanan

| Command/fungsi | Satu kalimat | Kapan dipakai | Jebakan utama | Day |
|---|---|---|---|---|
| `tstats` | Statistik langsung dari tsidx (indexed field atau data model terakselerasi), tanpa membaca raw event | Agregasi lebar/berulang, detection ES | `summariesonly=true` bisa diam-diam tidak lengkap; field search-time tidak terlihat tanpa data model | 01 |
| `transaction` | Menggabungkan event menjadi sesi dengan aturan `maxspan`/`maxpause`/`startswith`/`endswith` | ID dipakai ulang, butuh urutan/penanda, perlu raw event | Mahal; eviction diam-diam (`closed_txn=0`) | 02 |
| `first`/`last` | Nilai pertama/terakhir menurut urutan pemrosesan | Setelah `sort` eksplisit | Default: `first` = terbaru. Untuk waktu, pakai `earliest`/`latest` | 02 |
| `rex` | Ekstraksi field dengan named group (PCRE) atau substitusi `mode=sed` | Parsing ad hoc, prototipe extraction, masking tampilan | Default `_raw` (lambat); `max_match` default 1 | 03 |
| `eval` | Membuat/mengubah field dengan ekspresi dan fungsi | Normalisasi, flag, skor, waktu | Kutip tunggal = field, kutip ganda = string; null menular | 03 |
| `foreach` | Template yang diulang per field (multifield) atau per elemen (multivalue/JSON) | Banyak field serupa, skor dari banyak flag | `'<<FIELD>>'` untuk nama bertitik; inisialisasi akumulator | 04 |
| `lookup` | Enrichment dari tabel (CSV/KV/definition) | Konteks aset, IOC, subnet (CIDR) | `OUTPUT` menimpa; taruh setelah `stats` | 04 |
| `makeresults` | Membuat hasil sintetis di memori | Uji regex/logika/ambang | Berlipat di multi-server tanpa `splunk_server=local` | 04 |

Benang merah dari tabel di atas adalah pertanyaan "di mana data dibaca dan seberapa banyak". `tstats` cepat karena hanya membaca indeks (tsidx) dan summary data model, sehingga cocok untuk pertanyaan lebar, tetapi buta terhadap field yang tidak ter-indeks. `stats` membaca event tetapi bisa dikerjakan paralel di indexer, sedangkan `transaction` harus mengumpulkan event di search head dan menyimpannya di memori. Karena itu urutan pilihan yang sehat untuk pertanyaan agregat adalah `tstats`, lalu `stats`, dan baru `transaction` bila logika sesi memang tidak bisa diganti.

`rex` dan `eval` adalah alat membentuk data: `rex` mengambil bagian teks menjadi field, `eval` mengubah field menjadi flag, skor, atau format lain. Keduanya streaming, jadi murah bila dijalankan setelah data disaring. Kesalahan yang paling mahal di sini bukan soal performa melainkan soal hasil: kutip tunggal dan ganda yang tertukar, atau pencocokan tanpa `lower()` dan `urldecode()`, membuat detection diam-diam tidak menangkap apa pun.

`foreach`, `lookup`, dan `makeresults` adalah alat produktivitas. `foreach` menghindari puluhan baris `eval` yang mirip, `lookup` memberi konteks yang tidak ada di log (pemilik aset, daftar IOC, subnet), dan `makeresults` membuat data uji yang bisa diprediksi sehingga logika diuji sebelum menyentuh data produksi.

### 3.2 Search efisien

- **Ambil sesedikit mungkin data, saring sedini mungkin:** `index`/`sourcetype`/`host`/`source`, rentang waktu sempit, istilah spesifik, `TERM()`, `field::value`.
- **Hindari:** `index=*`, leading wildcard, `NOT`/`!=` sebagai filter utama, Verbose mode untuk pekerjaan rutin.
- **Urutan:** streaming dulu (`fields`, `eval`, `where`), transforming (`stats`), lalu `lookup`/`sort`/`table` di akhir.
- **Ganti yang mahal:** `transaction` diganti `stats`; `join` diganti `stats` atas gabungan sumber atau `lookup`; `dedup` diganti `stats latest()`; raw search diganti `tstats`.
- **Ukur:** Job Inspector (durasi, scanCount vs resultCount) dan Monitoring Console.

Rasio scanCount terhadap resultCount adalah angka paling berguna di Job Inspector. Bila search memindai 5 juta event untuk menghasilkan 200 baris, hampir semua kerja dibuang, dan filter seharusnya dipindah ke bagian awal (index, sourcetype, istilah spesifik). Optimasi yang benar tidak boleh mengubah jawabannya: versi sebelum dan sesudah harus menghasilkan jumlah baris yang sama. Jebakan paling halus ada pada `NOT` dan `!=`: `f!=x` hanya mengembalikan event yang memiliki field `f`, sedangkan `NOT f=x` juga mengembalikan event tanpa field itu. Mengganti satu dengan yang lain demi kecepatan bisa mengubah hasil investigasi.

### 3.3 Sumber daya SPL

- **research.splunk.com / ESCU:** detection siap pakai beserta prasyarat dan known FP.
- **SSE:** mencocokkan data dengan konten, cakupan ATT&CK.
- **Lantern:** panduan cara/praktik.
- **ES content management:** mengelola detection.
- **Istilah ES 8:** correlation search menjadi detection; notable menjadi finding; risk event menjadi intermediate finding; Incident Review menjadi analyst queue [S4].

Sebelum mengaktifkan detection dari ESCU, urutan pemeriksaannya selalu sama: baca bagian "how to implement" untuk tahu TA dan data model yang dibutuhkan, buktikan data model terisi dengan `| tstats count from datamodel=<DM> by sourcetype`, pastikan macro dan lookup yang dipakai ada, jalankan manual pada rentang beberapa hari, lalu bandingkan hasilnya dengan bagian "known false positives". Tuning dilakukan di filter macro (`*_filter`), bukan di logika inti, agar tidak hilang saat ESCU diperbarui.

## 3b. Peta konsep

```
                         PERTANYAAN INVESTIGASI
                                  |
          +-----------------------+------------------------+
          |                                                |
   AGREGAT LEBAR / BERULANG                        DETAIL / URUTAN / SESI
   tstats (tsidx, data model)                      search raw yang sempit
          |                                                |
   summariesonly? (cepat vs lengkap)            stats BY id  <-- default
          |                                     transaction  <-- ID dipakai ulang / penanda
          +-------------------+----------------------------+
                              |
                        NORMALISASI & FITUR
               rex (ekstrak/sed) | eval (case/if/coalesce/cidrmatch/match/urldecode)
                              | foreach (banyak field/flag)
                              |
                         KONTEKS
               lookup (aset, IOC, subnet CIDR) | inputlookup/outputlookup (baseline)
                              |
                         VALIDASI
               makeresults (uji logika) | Job Inspector (uji biaya)
                              |
                         SUMBER KONTEN
               research.splunk.com/ESCU | SSE | Lantern | ES content management
```

## 3c. Glosarium

| Istilah | Arti singkat |
|---|---|
| tsidx | File indeks time-series: lexicon term -> lokasi event |
| Data model acceleration | Summary tsidx berisi field data model, dibangun terjadwal di indexer |
| Summary range | Rentang waktu yang dijaga summary akselerasi |
| `summariesonly` | `tstats` hanya membaca summary (default false) |
| `prestats` | Format antara agar `tstats` bisa diteruskan ke `timechart`/`chart`/`stats` |
| `closed_txn` | 1 = transaksi tertutup normal, 0 = di-evict |
| Named capture group | `(?<nama>...)` di regex, menjadi field |
| `mode=sed` | Substitusi teks di hasil search |
| `OUTPUTNEW` | Lookup hanya mengisi field yang kosong |
| Match type CIDR/WILDCARD | Opsi lookup definition untuk mencocokkan subnet/pola |
| Distributable streaming | Command yang berjalan paralel di indexer |
| Dataset processing | Command yang butuh seluruh data di search head (`sort`, `eventstats`) |
| scanCount | Jumlah event yang dipindai (Job Inspector) |
| ESCU | ES Content Update, paket detection STRT |
| Analytic story | Kumpulan detection/investigasi/respons untuk satu ancaman |
| Finding / intermediate finding | Istilah ES 8 untuk notable / risk event [S4] |

## 3d. Latihan skenario dengan pembahasan

Jawab dulu tiap skenario sebelum membaca pembahasannya.

**Skenario 1.** Manajer meminta jumlah login gagal per sumber selama 90 hari untuk seluruh organisasi. Data model Authentication diakselerasi dengan summary range 30 hari. Kamu menjalankan `tstats summariesonly=true` dan mendapat angka yang tampak kecil.

Pembahasan: dengan `summariesonly=true`, `tstats` hanya membaca summary, sehingga hanya sekitar 30 hari terakhir yang terhitung. Untuk laporan 90 hari, pakai `summariesonly=false` (lebih lambat tetapi lengkap) atau minta summary range diperpanjang. Tulis di laporan rentang mana yang benar-benar tercakup. Ini contoh kenapa "hasil sedikit" tidak sama dengan "aktivitas sedikit" (Day 01).

**Skenario 2.** Kamu perlu durasi setiap sesi VPN. Log VPN memiliki `session_id` yang unik per sesi, dan setiap sesi punya event connect dan disconnect.

Pembahasan: karena ada ID unik, `stats earliest(_time) AS start latest(_time) AS end range(_time) AS duration BY session_id user` sudah cukup dan jauh lebih murah daripada `transaction`. `transaction` baru diperlukan bila ID dipakai ulang (misalnya Logon ID Windows yang bisa muncul lagi setelah reboot) sehingga butuh `maxspan`/`maxpause`, atau bila awal dan akhir sesi hanya bisa dikenali dari teks (Day 02).

**Skenario 3.** Rekanmu menulis timeline dengan `stats first(_time) AS waktu_awal BY src_ip` dan heran waktu awalnya selalu paling baru.

Pembahasan: `first()` mengambil nilai pertama menurut urutan pemrosesan. Search biasa mengembalikan event dari yang terbaru, jadi `first(_time)` adalah waktu terakhir. Untuk timeline, pakai `earliest(_time)` dan `latest(_time)` yang berbasis waktu (Day 02).

**Skenario 4.** Detection PowerShell terenkode di lab menangkap `-enc` tetapi melewatkan `-EncodedCommand` dan `-ec`.

Pembahasan: regex terlalu sempit. PowerShell menerima singkatan parameter apa pun yang tidak ambigu dan alias `-ec`, serta awalan `-` atau `/`. Perluas pola, lalu uji dengan `makeresults format=csv` berisi minimal tiga kasus positif (`-e`, `-EncodedCommand`, `/ec`) dan dua kasus negatif (parameter lain yang diawali huruf e, perintah tanpa parameter terenkode) sebelum detection dipakai (Day 03-04).

**Skenario 5.** Search investigasi kamu memakai `| lookup asset_list.csv ip AS src_ip OUTPUT owner` tepat setelah `index=proxy` dan berjalan 6 menit.

Pembahasan: lookup dijalankan untuk setiap event. Pindahkan ke setelah `stats ... BY src_ip`, sehingga lookup hanya berjalan sekali per IP unik. Hasilnya sama, durasinya turun drastis. Bila `asset_list.csv` berisi subnet, definisikan lookup definition dengan match type `CIDR(ip)` (Day 04-05).

## 4-6. Lab gabungan dan troubleshooting

**Prasyarat:** BOTS v1 (`index=botsv1`) dengan add-on yang disebut di repo [S1]; add-on CIM; akselerasi data model Web/Network_Traffic opsional. Cek nama field di instalasimu, karena versi TA lama (mis. TA Windows 4.8.3) memengaruhi nama field.

### Bagian A: Inventaris efisien (tstats, bagian 3.1 dan 3.2)

1. `| tstats count where index=botsv1 earliest=0 by sourcetype | sort - count`.
2. `| tstats count where index=botsv1 earliest=0 by _time span=1h | where count>0`: kapan data aktif. Catat rentang tanggal kejadian.
3. **Ukur:** bandingkan langkah 1 dengan `index=botsv1 earliest=0 | stats count by sourcetype` di Job Inspector.

**Cara membaca hasil Bagian A:** jumlah per sourcetype dari kedua cara harus sama persis. Bila berbeda, kemungkinan rentang waktu tidak sama atau ada event yang tidak ter-indeks seperti yang kamu kira. Grafik per jam dari langkah 2 biasanya memperlihatkan aktivitas yang terkonsentrasi di beberapa hari. Rentang itu yang dipakai di semua langkah berikutnya, karena dataset ini statis dan rentang relatif seperti "30 hari terakhir" tidak akan menemukan apa pun.

### Bagian B: Web defacement, metode (eval, rex, stats, lookup)

4. Temukan sumber yang paling banyak mengakses situs target lewat `stream:http`:
   ```
   index=botsv1 sourcetype=stream:http site="imreallynotbatman.com" earliest=0
   | stats count dc(uri) AS uris values(http_user_agent) AS ua BY src_ip
   | sort - count
   ```
5. Beri skor request mencurigakan dengan pola `eval` Day 03 bagian 4.3. Gunakan `foreach f_*` untuk menjumlahkan flag (Day 04 bagian 4.2).
6. Tambahkan konteks: buat `lab_assets.csv` untuk IP internal web server dan workstation (berdasarkan observasimu sendiri), lalu `lookup ... OUTPUTNEW` setelah `stats`.
7. Cari indikasi upload atau brute force login ke CMS: `http_method=POST`, pola `uri` login, dan form data bila terekstrak. Gunakan `rex` bila parameter tidak ter-parse, cek nama field form data di stream:http.
8. Bangun timeline per penyerang dengan `stats earliest(_time) latest(_time) count BY src_ip uri`. Jangan memakai `first`/`last` untuk waktu (Day 02).

**Cara membaca hasil Bagian B:** sumber dengan jumlah request sangat tinggi, `dc(uri)` besar, dan user agent yang menyebut nama tool pemindai biasanya adalah tahap reconnaissance. Sumber lain dengan request lebih sedikit tetapi banyak `POST` ke halaman login adalah kandidat brute force. Bedakan keduanya di catatanmu, karena di insiden nyata dua aktivitas itu bisa berasal dari IP berbeda milik aktor yang sama. Skor dari `eval` hanya alat urut; setiap `src_ip` dengan skor tinggi tetap perlu dibaca event-nya.

### Bagian C: Sesi dan urutan (transaction vs stats)

9. Buat sesi web per `src_ip` dengan `transaction src_ip maxpause=5m`, lalu versi `stats` + `streamstats` (Day 02 variasi tantangan). Bandingkan jumlah sesi dan durasi job.
10. Jawab dengan alasan: mana yang dipakai untuk laporan, mana untuk scheduled search?

**Cara membaca hasil Bagian C:** jumlah sesi dari `transaction` dan dari `streamstats` bisa berbeda tipis. Penyebab umumnya adalah transaksi yang ter-evict (`closed_txn=0`) atau batas `maxevents` (default 1000) yang memotong sesi panjang. Catat selisihnya dan penyebabnya. Untuk scheduled search, pilihan yang wajar adalah versi `streamstats`/`stats` karena lebih murah dan tidak bergantung memori search head.

### Bagian D: Validasi logika (makeresults)

11. Ambil satu regex/ambang dari Bagian B, lalu uji dengan `makeresults format=csv data=...` berisi 3 kasus positif dan 2 negatif yang kamu tulis sendiri.

### Bagian E: Konten siap pakai (5.3)

12. Di research.splunk.com, cari detection untuk aktivitas web/brute force yang relevan. Cek apakah data BOTS v1 memenuhi prasyaratnya (`tstats ... from datamodel=Web by sourcetype`).

**Variasi lab:** ulangi Bagian B untuk skenario ransomware pada workstation `we8105desk` dengan sumber Sysmon dan registry Windows. Fokus pada metode: proses apa yang muncul pertama kali di host itu, koneksi keluar apa yang menyertainya, dan perubahan file apa yang terjadi dalam jumlah besar. Pakai `tstats` untuk inventaris sourcetype host itu, `stats` untuk timeline, dan `rex`/`eval` untuk mengambil nama file dan ekstensi.

**Hasil yang sebaiknya tersimpan:**
- Rentang waktu kejadian BOTS v1 diketahui (Bagian A).
- Ada daftar `src_ip` mencurigakan beserta skor dan alasannya.
- Ada timeline penyerang berbasis `earliest`/`latest`.
- Ada perbandingan `transaction` vs `stats` dengan angka.
- Ada uji `makeresults` untuk satu logika.
- Ada satu detection ESCU yang dinilai kesiapan datanya.

**Troubleshooting ringkas:**

| Gejala | Penyebab umum | Perbaikan |
|---|---|---|
| Tidak ada hasil sama sekali | Rentang waktu default (24 jam) | `earliest=0` atau set rentang 2016 |
| Field kosong di stream:http | TA Stream tidak terpasang/versi beda | Pasang add-on yang disebut repo [S1]; cek `fieldsummary` |
| `tstats` data model kosong | CIM/akselerasi belum aktif | Day 01 bagian 4.4 |
| Search lambat | `index=*`, Verbose mode, `transaction` atas semua data | Day 05 |

## 7. Kesalahan umum dan jebakan (review)

- `first()` untuk "waktu pertama" (Day 02).
- `summariesonly=true` saat investigasi historis (Day 01).
- `rex` di `_raw` padahal field sudah ada (Day 03).
- Kutip tunggal vs ganda tertukar di `eval`/`foreach` (Day 03-04).
- `lookup` sebelum `stats` (Day 04).
- `NOT` vs `!=` mengubah hasil, bukan hanya biaya (Day 05).
- Mengaktifkan detection tanpa cek prasyarat data (Day 06).
- Rentang waktu relatif (`earliest=-30d`) pada dataset statis 2016 (bagian 4-6, Bagian A).

## 8. Catatan terkini

- BOTS v1 dibuat dengan Splunk 6.5.2 dan versi add-on lama [S1]. Pada Splunk 10.x dan add-on terbaru, nama field atau sourcetype bisa berbeda dari write-up lama di internet. Selalu verifikasi dengan data di instance Splunk-mu.
- Banyak write-up publik dan lab CTF (mis. CyberDefenders "Boss Of The SOC v1", proyek kelas samsclass) memakai dataset ini [S2][S3]. Lab di Day ini sudah memuat metode yang dibutuhkan, jadi write-up itu tidak perlu dibuka; bila tetap dibaca, pakai hanya untuk membandingkan metode, bukan jawaban.

## 9. Cheat sheet minggu 1

```
tstats  | tstats [summariesonly=] [prestats=] <fn> [from datamodel=DM.Root] where <idx/dm fields> by <f> [span=]
trans   | transaction <ids> maxspan= maxpause= startswith= endswith= keepevicted=  -> duration eventcount closed_txn
stats   | stats earliest(_time) latest(_time) range(_time) count values() dc() BY <id>
order   first/last = urutan proses | earliest/latest = waktu
rex     | rex field=F "(?<x>re)" max_match=0 | rex field=F mode=sed "s/a/b/g"
eval    | eval a=case(..,true(),..), b=if(), c=coalesce(), d=cidrmatch("cidr",ip), e=match(f,"re"), u=lower(urldecode(uri))
foreach | eval s=0 | foreach f_* [eval s=s+'<<FIELD>>']
lookup  | stats ... | lookup def key AS field OUTPUTNEW cols   (CIDR(f)/WILDCARD(f) di definition)
mkres   | makeresults format=csv data="a,b\n1,2" | makeresults count=N | streamstats count AS n | eval _time=now()-n*60
EFISIEN index/sourcetype/waktu/istilah spesifik -> fields -> streaming -> stats -> lookup/sort/table ; ukur Job Inspector
KONTEN  research.splunk.com/ESCU | SSE | Lantern | ES content mgmt ; ES8: detection/finding/intermediate finding/analyst queue
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | GitHub splunk/botsv1: BOTS v1 dataset | https://github.com/splunk/botsv1 | primer | 2016 (dataset); diakses 2026-10-07 | Tinggi. Index, sourcetype, add-on, lisensi CC0 |
| S2 | CyberDefenders: Boss Of The SOC v1 (lab) | https://cyberdefenders.org/labs/15 | sekunder/komunitas | tanggal tidak tercatat | Sedang. Hanya untuk deskripsi skenario; isi lab tidak dipakai agar tidak membocorkan jawaban |
| S3 | samsclass.info: Boss of the SOC v1: Threat Hunting with Splunk | https://samsclass.info/50/proj/botsv1 | komunitas (materi kelas) | tanggal tidak tercatat | Rendah-sedang. Hanya untuk deskripsi skenario |
| S4 | ES 8.7 Glossary | https://help.splunk.com/en/splunk-enterprise-security-8/release-notes-and-resources/8.7/where-to-find-help/glossary | primer | diakses 2026-10-07 | Tinggi |

Sumber Day 01-06 dirujuk ulang secara implisit di ringkasan; lihat tabel Sumber masing-masing Day.

**Catatan sumber:** nama field per sourcetype BOTS v1 pada Splunk 10.x dan add-on terbaru belum terkonfirmasi, jadi cek dengan `fieldsummary` di instance-mu. Deskripsi dua skenario BOTS v1 berasal dari sumber komunitas [S2][S3]. Latihan skenario di bagian 3d fiktif dan merangkum isi Day 01-05.
