---
day: 13
title: 'transaction dan first/last: mengelompokkan event, dan kapan lebih baik memakai stats'
researched_on: 2026-10-07
versions_checked: Splunk Enterprise SPL Search Reference 10.2 (transaction), Search Manual 10.6 (About transactions), SPL Search Reference 10.0 (event order functions); Splunk Enterprise terbaru 10.6
---

# Day 13: transaction dan first/last, serta kapan stats lebih tepat

Cakupan: mengelompokkan event menjadi sesi dengan `transaction`, memilih `stats` sebagai alternatif yang lebih murah, dan membedakan `first`/`last` dari `earliest`/`latest`.

## Ide inti

Sebagian pertanyaan investigasi bukan soal hitungan, melainkan soal urutan dan rentang waktu: berapa lama sesi RDP ke jump host itu berlangsung, apakah ada rangkaian login gagal ke VPN yang diakhiri satu login berhasil, klien mana yang mengirim ratusan request web dalam beberapa menit. `transaction` menjawabnya dengan menyatukan beberapa event menjadi satu transaksi, lalu memberi `duration`, `eventcount`, dan `closed_txn`. Harganya mahal: transaksi yang belum tertutup ditahan di memori dan pekerjaannya tidak bisa dipecah ke indexer seperti `stats`, sehingga dokumentasi Splunk sendiri menempatkan `stats` sebagai pilihan utama di sebagian besar kasus [S2]. Day ini sebenarnya melatih satu keputusan: kapan sesi harus benar-benar direkonstruksi, dan kapan cukup diringkas per ID. Dasar SPL dan `stats` sudah ada di Day 02; Day ini menambahkan pengelompokan event menjadi sesi dan satu jebakan urutan yang sering lolos, yaitu `first`/`last`.

Analoginya dekat dengan pekerjaan merekonstruksi satu sesi dari banyak baris log, misalnya mengikuti satu call flow di log SIP dari INVITE sampai BYE: yang dicari adalah kisah satu sesi, bukan rekap semua sesi. Batas analoginya ada di biaya dan keutuhan. Rekonstruksi manual bisa diteruskan sampai selesai, sedangkan `transaction` dibatasi memori dan jumlah event, sehingga sesi tertua bisa dibuang di tengah jalan tanpa pesan error. Untuk rekap biasa, `stats` adalah `sort | uniq -c` dengan agregasi per kolom dan jauh lebih murah, dengan batas bahwa hasilnya kehilangan event mentah, jadi field yang masih kamu butuhkan harus diselamatkan lewat `values()` atau `list()`.

**Kapan relevan:** ID pengelompokan dipakai ulang sehingga butuh batas waktu atau jeda, awal dan akhir sesi ditandai teks tertentu, atau kamu perlu melihat raw event yang tergabung dalam satu sesi [S2].
**Kapan bukan jawaban:** ada ID yang unik di dalam rentang search (session ID, `Logon_ID` yang tidak dipakai ulang, `trade_id`) dan yang kamu butuhkan hanya durasi, hitungan, atau nilai unik. Pakai `stats`. `transaction` juga bukan pilihan untuk search terjadwal yang berjalan tiap beberapa menit, karena beban memori dan waktu jalannya menumpuk di search head. Dan untuk urutan waktu, `first`/`last` bukan pengganti `earliest`/`latest`.

## 1. Konsep inti

### 1.1 Cara kerja transaction

`transaction` mengelompokkan event yang punya nilai sama pada field yang disebut (field-list), lalu menerapkan aturan batas [S1]:
- `maxspan`: jarak maksimal antara event pertama dan terakhir dalam satu transaksi. Default tidak terbatas (-1).
- `maxpause`: jeda maksimal antar event berturut-turut. Default tidak terbatas.
- `maxevents`: jumlah event maksimal per transaksi. Default 1000.
- `startswith` / `endswith`: ekspresi search atau eval yang menandai awal/akhir transaksi.
- `connected` (default true) dan `unifyends`: mengatur bagaimana event dengan field yang tidak lengkap boleh ikut bergabung.
- `keeporphans` (default false): ikut keluarkan event yang tidak masuk transaksi mana pun.
- `keepevicted` (default false): keluarkan juga transaksi yang "diusir" karena batas memori.

Field yang ditambahkan [S1]:
- `duration`: selisih waktu event pertama dan terakhir.
- `eventcount`: jumlah event dalam transaksi.
- `closed_txn`: 1 jika transaksi tertutup normal, 0 jika di-evict.
- `field_match_sum` dan `linecount`: field pelacakan internal.

### 1.2 Kenapa mahal

Ada tiga sumber biaya:
1. `transaction` harus memegang transaksi yang masih terbuka di memori sampai kriteria penutupnya terpenuhi. Opsi `maxopentxn` dan `maxopenevents` membatasinya. Bila batas tercapai, transaksi tertua di-evict (LRU) [S1]. Akibatnya, hasil bisa diam-diam tidak lengkap kecuali kamu memeriksa `closed_txn` atau menyalakan `keepevicted`.
2. Ia bergantung pada urutan waktu. Event harus dalam urutan waktu menurun sebelum `maxspan` diterapkan. Jika urutannya sudah diubah, misalnya oleh `sort`, kembalikan dengan `| sort -_time` tepat sebelum `transaction` [S1].
3. Ia tidak bisa dipecah ke indexer seperti `stats`. `stats` bisa melakukan pra-agregasi di indexer, lalu hasil parsialnya digabung di search head. Karena itu dokumentasi menyebut `stats` lebih efisien di lingkungan terdistribusi [S2]. Detail eksekusinya, cek di "Search under the hood" / dokumentasi distributed search.

Praktisi di Splunk Community berulang kali memberi saran yang sama [S5]:
- Ganti `transaction` dengan `stats`, `eventstats`, atau `streamstats` bila bisa.
- Jika tetap memakai `transaction`, persempit data dulu (index, sourcetype, rentang waktu) dan beri `maxspan`.

Saran ini konsisten dengan dokumentasi primer [S2].

### 1.3 Pola "stats sebagai transaksi semu"

Dokumentasi memberi contoh kesetaraan [S2]:

```
... | transaction trade_id | chart count by duration
... | stats range(_time) AS duration BY trade_id | chart count by duration
```

Kedua baris memberi hasil sama bila `trade_id` unik per transaksi. Fungsi `stats` yang paling sering menggantikan `transaction`:

| Kebutuhan | Fungsi stats |
|---|---|
| Waktu mulai/akhir | `earliest(_time)`, `latest(_time)` atau `min(_time)`, `max(_time)` |
| Durasi | `range(_time)` |
| Jumlah event | `count` |
| Nilai yang muncul | `values(field)` (unik, terurut), `list(field)` (semua, sesuai urutan) |
| Hitung kondisi | `count(eval(action="failure"))` (boleh di `stats`, tidak di `tstats`; lihat Day 25) |

Yang tidak dimiliki `stats` adalah `maxspan`/`maxpause` dan penanda `startswith`/`endswith`. Jika ID dipakai ulang (mis. IP klien yang sama datang lagi besok), `stats` akan menggabungkan dua sesi menjadi satu. Kasus seperti inilah tempat `transaction` layak dipakai [S2][S5].

Alternatif di tengah: hitung batas sesi dengan `streamstats` (mis. jeda dari event sebelumnya), beri nomor sesi, lalu `stats ... BY session_id`. Pola ini lebih maju; cukup dikenali dulu.

### 1.4 first/last vs earliest/latest

Ini jebakan yang sering menipu, bahkan analyst berpengalaman [S3][S4]:
- `first(field)`: nilai pertama yang dilihat perintah statistik. Karena urutan default hasil search adalah waktu menurun, nilai ini biasanya yang paling baru.
- `last(field)`: nilai terakhir yang dilihat, biasanya yang paling lama.
- `earliest(field)` / `latest(field)`: berdasarkan waktu event, tidak bergantung urutan pemrosesan.
- Dokumentasi menyarankan memakai `earliest()` bila yang kamu cari adalah nilai pertama menurut waktu. `first`/`last` paling aman bila didahului `sort` [S3].

Jadi, untuk timeline investigasi ("IP pertama yang dipakai akun ini"), gunakan `earliest(src_ip)`, bukan `first(src_ip)`. Banyak orang terkecoh karena nama `first` terdengar seperti "paling awal".

Varian `earliest_time()` dan `latest_time()` mengembalikan timestamp saat nilai itu muncul. Ini berguna untuk kolom firstSeen/lastSeen, cek ketersediaannya di versi lab-mu.

**Tanpa ES:** `transaction`, `stats`, dan semua fungsi di atas adalah fitur inti Splunk Enterprise, tidak butuh ES. Di ES, kamu akan melihat pola `stats earliest/latest` (sering dalam bentuk `min(_time) as firstTime max(_time) as lastTime`) di hampir setiap detection, karena alasan biaya yang sama. Lihat contoh security_content di Day 25.

## 2. Contoh SPL dan langkah di ES

> Keluaran berlabel ilustrasi. Asumsi: BOTS v1 di `index=botsv1`; log Windows Security dari TA Windows dengan field gaya klasik (`EventCode`, `Account_Name`, `Logon_ID`, `Source_Network_Address`). Cek nama field di lab-mu: event berformat XML memakai nama lain, misalnya `TargetLogonId`.
>
> Jebakan format klasik: event 4624 dan 4625 memuat dua blok akun (Subject dan New Logon / Account For Which Logon Failed). TA Windows biasanya mengekstrak `Account_Name` dan `Logon_ID` sebagai multivalue, misalnya `Logon_ID` berisi `0x3E7` (Subject) dan ID sesi yang sebenarnya. Cek dulu dengan `| eval n=mvcount(Logon_ID)`. Bila bernilai 2, ambil nilai kedua dengan `eval logon_id=mvindex(Logon_ID, 1)` dan pakai field itu untuk pengelompokan, atau pakai format XML (`TargetLogonId`, `TargetUserName`) yang tidak ambigu. Cek urutan nilai multivalue di TA versi lab-mu.

### 2.1 Durasi sesi logon Windows dengan transaction

**Tujuan:** menghitung durasi setiap sesi logon, dari 4624 (logon) sampai 4634/4647 (logoff), cek arti event ID di Microsoft Learn.

```
index=botsv1 sourcetype="WinEventLog:Security" (EventCode=4624 OR EventCode=4634 OR EventCode=4647)
| transaction host Logon_ID startswith="EventCode=4624" endswith="EventCode IN (4634, 4647)" maxspan=12h keepevicted=true
| table _time host Account_Name Logon_ID duration eventcount closed_txn
| sort - duration
```

| Bagian | Penjelasan |
|---|---|
| filter awal | Ambil hanya event yang relevan. Memperkecil data adalah cara termurah mempercepat `transaction` |
| `transaction host Logon_ID` | Kelompokkan per host dan Logon ID. Logon ID unik di dalam satu host, bukan antar host, jadi `host` wajib ikut |
| `startswith=... endswith=...` | Transaksi dibuka oleh 4624 dan ditutup oleh logoff. Cek sintaks `IN` di dalam `endswith`. Jika gagal, pakai `endswith="EventCode=4634 OR EventCode=4647"` dengan tanda kutip yang benar |
| `maxspan=12h` | Batas aman agar sesi yang tidak pernah ditutup tidak menumpuk di memori |
| `keepevicted=true` | Tampilkan juga transaksi yang tidak tertutup, untuk dianalisis |
| `table ... closed_txn` | `closed_txn=0` berarti tidak ada logoff yang cocok dalam batas, atau transaksi ter-evict |

Keluaran ilustrasi:

```
host        Account_Name  Logon_ID   duration  eventcount  closed_txn
we8105desk  bob.smith     0x3E7A11   28455     2           1
we8105desk  svc_backup    0x1F002B   43200     1           0
```

**Cara membaca hasil:** baris kedua adalah sesi tanpa logoff dalam 12 jam. Penyebabnya bisa layanan, log yang hilang, atau sesi yang masih aktif. Jangan langsung menyebut anomali sebelum mengecek tipe logon (`Logon_Type`).
**Kapan gagal/lambat:** rentang waktu panjang tanpa filter; Logon_ID dipakai ulang setelah reboot (karena itu ada `maxspan`); event 4634 tidak dikumpulkan karena audit policy; `Logon_ID` multivalue di event 4624 sehingga transaksi salah gabung (lihat catatan jebakan di atas).

### 2.2 Versi stats untuk kebutuhan yang sama

```
index=botsv1 sourcetype="WinEventLog:Security" (EventCode=4624 OR EventCode=4634 OR EventCode=4647)
| stats earliest(_time) AS start latest(_time) AS end range(_time) AS duration
        values(EventCode) AS codes values(Account_Name) AS users count BY host Logon_ID
| where mvcount(codes) > 1
| convert ctime(start) ctime(end)
| sort - duration
```

- `range(_time)`: durasi tanpa `transaction`.
- `values(EventCode)`: memeriksa apakah logon dan logoff sama-sama ada.
- `where mvcount(codes) > 1`: buang sesi yang hanya punya salah satu event.
- **Batasan:** jika Logon_ID terpakai ulang di host yang sama dalam rentang search, dua sesi akan tergabung. Itu tidak terdeteksi tanpa logika tambahan. Persempit rentang waktu atau kembali ke `transaction` dengan `maxspan`.

**Eksperimen yang wajib dicoba:** jalankan bagian 2.1 dan 2.2 di rentang yang sama, lalu bandingkan jumlah baris dan durasi job (Job > Inspect Job). Hasil yang diharapkan: `stats` jauh lebih cepat, dengan hasil sama atau hampir sama bila ID tidak dipakai ulang.

### 2.3 Rangkaian brute force yang diakhiri sukses

**Tujuan:** menemukan sumber yang gagal berkali-kali lalu berhasil login dalam 15 menit. Ini kasus khas yang membutuhkan urutan.

```
index=botsv1 sourcetype="WinEventLog:Security" (EventCode=4625 OR EventCode=4624)
| eval outcome=if(EventCode=4625, "fail", "success")
| transaction Source_Network_Address Account_Name maxspan=15m startswith="outcome=fail" endswith="outcome=success"
| where eventcount >= 6
| table _time Source_Network_Address Account_Name eventcount duration
```

- `eval outcome=...` dibuat lebih dulu agar `startswith`/`endswith` sederhana dan mudah dibaca.
- `transaction ... startswith="outcome=fail" endswith="outcome=success"`: hanya transaksi yang dimulai dengan gagal dan diakhiri berhasil.
- `where eventcount >= 6`: minimal 5 gagal + 1 sukses. Ambang ini asumsi.

Versi `stats` yang mendekati:

```
... | eval outcome=if(EventCode=4625,"fail","success")
| bin _time span=15m
| stats count(eval(outcome="fail")) AS fails count(eval(outcome="success")) AS success
        earliest(_time) AS first_seen BY _time Source_Network_Address Account_Name
| where fails >= 5 AND success >= 1
```

**Perbedaan penting:** versi `stats` dengan `bin` tidak menjamin bahwa sukses terjadi setelah gagal, dan rangkaian yang melewati batas bucket 15 menit bisa terpecah. Untuk deteksi terjadwal biasanya masih bisa diterima karena murah. Untuk investigasi urutan, `transaction` lebih tepat. Trade-off inilah yang harus bisa kamu jelaskan.

### 2.4 first/last vs earliest/latest dalam satu query

```
index=botsv1 sourcetype="WinEventLog:Security" EventCode=4624 Account_Name="bob.smith"
| stats first(Source_Network_Address) AS first_fn last(Source_Network_Address) AS last_fn
        earliest(Source_Network_Address) AS earliest_fn latest(Source_Network_Address) AS latest_fn
```

Keluaran ilustrasi:

```
first_fn      last_fn       earliest_fn   latest_fn
192.168.250.70 192.168.250.20 192.168.250.20 192.168.250.70
```

**Cara membaca hasil:** `first_fn` sama dengan `latest_fn` dan `last_fn` sama dengan `earliest_fn`, karena hasil search mengalir dari yang terbaru [S3]. Jika kamu menambahkan `| sort 0 _time` sebelum `stats`, `first`/`last` akan berbalik. Hasil `earliest`/`latest` tidak berubah.

### 2.5 Di ES (generik)

- Di panel investigasi ES, timeline aktivitas aset/identitas pada dasarnya dibangun dari pola `earliest/latest` per entitas. Nama panel bervariasi antar versi ES, cek di ES 8.x.
- Saat membuat atau menyunting detection (correlation search di versi lama), hindari `transaction` di search yang berjalan tiap beberapa menit. Gunakan `tstats`/`stats` (Day 25, Day 36).

## 3. Lab praktik

**Data:** BOTS v1, atau log Security dari VM Windows lab.

1. Jalankan `index=botsv1 sourcetype="WinEventLog:Security" | stats count by EventCode | sort - count` untuk mengetahui event ID apa yang tersedia.
2. Jalankan bagian 2.1. Catat jumlah transaksi dengan `closed_txn=0`.
3. Jalankan bagian 2.2 di rentang yang sama. Bandingkan jumlah baris dan durasi job di Inspect Job.
4. Jalankan bagian 2.3. Jika tidak ada hasil di BOTS v1, turunkan ambang ke `eventcount >= 3`, atau buat datanya sendiri: di VM Windows lab, coba login RDP/lokal dengan password salah 5 kali, lalu benar.
5. Jalankan versi `stats` bagian 2.3 dan cari kasus yang berbeda hasilnya. Jelaskan perbedaannya.
6. Jalankan bagian 2.4, lalu ulangi dengan `| sort 0 _time` sebelum `stats`. Catat perubahannya.

**Hasil yang sebaiknya tersimpan:**
- Ada angka durasi job `transaction` vs `stats`.
- Bisa menjelaskan arti `closed_txn=0`.
- Bisa menunjukkan satu kasus di mana `stats` + `bin` memecah rangkaian.
- Bisa menjelaskan perbedaan `first` vs `earliest` dengan bukti dari langkah 6.

**Variasi tantangan:** dengan `sourcetype=stream:http` di BOTS v1, buat sesi web per `src_ip` dengan `maxpause=5m`, lalu cari sesi dengan `eventcount` sangat tinggi dan `duration` pendek (indikasi scanning/brute force web). Setelah itu tulis versi `streamstats` yang menandai jeda > 5 menit sebagai sesi baru. Cek nama field `src_ip` di sourcetype itu.

## 4. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Durasi transaksi aneh/negatif atau `maxspan` tidak bekerja | Urutan event berubah (mis. setelah `sort`) | Tambahkan `\| sort -_time` tepat sebelum `transaction` [S1] |
| Jumlah transaksi lebih sedikit dari dugaan | Transaksi di-evict karena batas memori; `maxevents` 1000 tercapai | `keepevicted=true`, cek `closed_txn`; persempit data; naikkan batas hanya jika paham dampaknya [S1] |
| Dua sesi berbeda tergabung | ID dipakai ulang tanpa `maxspan`/`maxpause` | Tambah `maxspan`/`maxpause` atau `startswith`/`endswith` [S2] |
| `startswith`/`endswith` tidak pernah cocok | Kutipan salah; field belum ada saat itu | Buat field dengan `eval` lebih dulu (bagian 2.3); uji ekspresinya dengan `search` terpisah |
| Search sangat lambat | `transaction` atas data besar | Filter awal, rentang lebih pendek, atau ganti `stats` [S2][S5] |
| `first()` memberi nilai "terbaru" | Urutan default menurun | Pakai `earliest()` untuk urutan waktu [S3] |

## 5. Kesalahan umum dan jebakan

- Memakai `transaction` sebagai default. Dokumentasi menempatkan `stats` sebagai pilihan utama kecuali ada alasan spesifik [S2].
- Mengira `first` = paling awal. Justru biasanya paling baru [S3][S4].
- Tidak memeriksa `closed_txn`. Transaksi yang ter-evict hilang dari hasil secara diam-diam bila `keepevicted=false` (default) [S1].
- Lupa `host` di field-list untuk ID yang hanya unik per host (Logon ID, PID).
- `transaction` di scheduled search yang sering berjalan. Ini membebani search head dan berisiko skipped searches.
- `[komunitas]` Thread Splunk Community ("transaction vs stats", "Optimize transaction query", "Alternative of transaction") konsisten menyarankan `stats`/`eventstats`/`streamstats` dan pembatasan data sebelum `transaction` [S5]. Saran ini dikonfirmasi dokumentasi primer [S2].

## 6. Catatan terkini

- Sintaks dan default `transaction` di referensi 10.2 konsisten dengan versi 9.x. Tidak ada perubahan perilaku besar yang tercatat; bila ragu, cek release notes 10.4/10.6.
- Dokumentasi "About transactions" ada untuk Splunk Enterprise 9.1 sampai 10.6 dan Cloud 10.0.2503 dengan isi panduan yang sama [S2].
- Halaman event order functions kini juga tersedia untuk SPL2 dengan definisi `first/last` yang sama. Jangan bingung saat menemukan dokumentasi SPL2 ketika mencari referensi. SPL2 dipakai di Edge Processor/Ingest Processor, dan SPL "klasik" tetap dipakai di Search & Reporting dan ES, cek cakupan SPL2 di versi-mu.

## 7. Cheat sheet

```
transaction <fields> [maxspan=] [maxpause=] [maxevents=1000] [startswith=] [endswith=]
            [keepevicted=f] [keeporphans=f]  -> duration, eventcount, closed_txn
  * butuh urutan waktu menurun (| sort -_time sebelum transaction bila urutan berubah)
  * mahal: memori + tidak terdistribusi -> filter dulu, beri maxspan

stats "transaksi semu":
  stats earliest(_time) AS start latest(_time) AS end range(_time) AS duration count values(x) BY <id>

PILIH transaction bila: ID dipakai ulang (butuh maxspan/maxpause) | penanda start/end teks | perlu raw event
PILIH stats bila: ada ID unik | cukup durasi/hitungan/nilai | scheduled search

first()/last()  = urutan PEMROSESAN (default: first = terbaru, last = terlama)
earliest()/latest() = urutan WAKTU  -> pakai ini untuk timeline
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Kamu ingin tahu IP pertama yang dipakai sebuah akun dalam rentang search, lalu menulis `| stats first(Source_Network_Address) AS ip_pertama BY Account_Name`. Kenapa hasilnya justru cenderung IP terbaru?

<details><summary>Jawaban</summary>

`first()` dan `last()` mengikuti urutan pemrosesan, bukan urutan waktu. Hasil search default mengalir dari event terbaru ke terlama, jadi nilai pertama yang dilihat perintah statistik biasanya justru yang paling baru. Untuk urutan waktu pakai `earliest()` dan `latest()` yang menilai `_time` event dan tidak bergantung urutan masuknya. `first`/`last` baru aman bila kamu sendiri yang menentukan urutannya dengan `sort` lebih dulu. Lihat bagian 1.4 dan 2.4.

</details>

**2. Skenario keputusan.** Kamu diminta membuat detection terjadwal tiap lima menit untuk pola "lima login gagal lalu satu login berhasil dari sumber yang sama". Mana yang paling tepat dijadikan dasar search-nya?

- A. `transaction Source_Network_Address Account_Name maxspan=15m startswith="outcome=fail" endswith="outcome=success"`, karena hanya ini yang menjamin urutannya benar.
- B. `bin _time span=15m` lalu `stats count(eval(outcome="fail")) ... BY _time Source_Network_Address Account_Name`, dengan kesadaran bahwa urutan tidak dijamin.
- C. `transaction` tanpa `maxspan` supaya tidak ada rangkaian yang terpotong batas waktu.

<details><summary>Jawaban</summary>

B. Untuk search yang berjalan tiap lima menit, yang menentukan adalah biaya: `stats` bisa melakukan pra-agregasi di indexer, sedangkan `transaction` menahan transaksi terbuka di memori dan tidak terdistribusi. Konsekuensinya diterima secara sadar: versi `bin` plus `stats` tidak menjamin sukses terjadi setelah gagal, dan rangkaian yang melintasi batas bucket bisa terpecah, yang untuk detection biasanya masih dapat diterima karena bisa divalidasi saat triage. A benar secara urutan dan cocok untuk investigasi ad hoc, tetapi mahal bila dijalankan terus-menerus dan berisiko membuat search terlewat. C lebih buruk lagi: tanpa `maxspan`, sesi yang tidak pernah tertutup menumpuk sampai batas memori dan transaksi tertua dibuang. Lihat bagian 1.2, 1.3, dan 2.3.

</details>

**3. Pertanyaan jebakan.** "Search `transaction` saya mengembalikan 40 baris, jadi di rentang itu memang ada 40 sesi." Apa yang salah dari kesimpulan ini?

<details><summary>Jawaban</summary>

Jumlah baris hasil bukan jumlah sesi yang sebenarnya. Transaksi yang melewati batas memori (`maxopentxn`, `maxopenevents`) di-evict dan, karena `keepevicted` default false, hilang dari hasil tanpa peringatan apa pun; batas `maxevents` yang default 1000 juga memotong transaksi panjang. Cara memeriksanya adalah menyalakan `keepevicted=true` lalu membaca `closed_txn`: nilai 0 berarti transaksi tidak tertutup normal. Sesi tanpa event penutup juga bisa muncul karena logoff tidak dikumpulkan audit policy, bukan karena sesinya aneh. Lihat bagian 1.1, 1.2, dan 4.

</details>

**4. Jelaskan ulang.** Jelaskan ke analyst L1 yang baru belajar SPL, dalam tiga kalimat, kapan dia sebaiknya memakai `transaction` dan kapan `stats`.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh jawaban: "Kalau kamu cuma butuh durasi, jumlah event, atau daftar nilai per satu ID yang unik, pakai `stats ... BY id` dengan `range(_time)` untuk durasinya, karena jauh lebih murah dan bisa dikerjakan paralel di indexer. Pakai `transaction` kalau ID-nya dipakai ulang sehingga kamu butuh `maxspan` atau `maxpause` sebagai pemisah sesi, kalau awal dan akhir sesi ditandai teks tertentu, atau kalau kamu memang perlu melihat raw event yang tergabung. Kalau terpaksa memakai `transaction`, persempit dulu index, sourcetype, dan rentang waktunya, lalu cek `closed_txn` sebelum percaya jumlah hasilnya."

Kesalahan yang sering muncul: menyebut `transaction` sebagai cara "yang benar" dan `stats` sebagai jalan pintas, padahal dokumentasi menempatkan `stats` sebagai pilihan utama; lupa menyebut bahwa `stats` akan menggabungkan dua sesi menjadi satu bila ID dipakai ulang di rentang search; dan lupa `host` di field-list untuk ID yang hanya unik per host seperti Logon ID dan PID. Lihat bagian 1.2, 1.3, dan 5.

</details>

**5. Interview question (English).** "Splunk's own documentation says to prefer stats over transaction. So when do you still reach for transaction?"

<details><summary>Sample answer</summary>

"I default to stats, because it aggregates in parallel on the indexers and gives me most of what transaction does: range of _time for duration, count for event volume, values or list for what happened inside the group. I reach for transaction when the grouping key gets reused and I need a time boundary to separate one session from the next, when the start and end of a session are marked by specific text rather than a key, or when I actually need to read the raw events that belong together. When I do use it, I narrow index, sourcetype and time range first, always set maxspan, and check closed_txn, because evicted transactions silently disappear from the results by default, so the row count can look reassuring while the data is incomplete. And I never put transaction in a detection that runs every few minutes; that work belongs in stats or tstats."

What makes this answer strong: it names the specific stats functions that replace transaction instead of waving at "stats is faster", gives three concrete conditions that justify the expensive command, and shows awareness that the real risk is silently incomplete results rather than slowness alone.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | SPL Search Reference: transaction (Splunk Enterprise 10.2) | https://help.splunk.com/en/splunk-enterprise/spl-search-reference/10.2/search-commands/transaction | primer | diakses 2026-10-07 | Tinggi. Opsi, default, field, urutan waktu |
| S2 | Search Manual: About transactions (10.6) | https://help.splunk.com/en/splunk-enterprise/search/search-manual/10.6/group-and-correlate-events/about-transactions | primer | diakses 2026-10-07 | Tinggi. Panduan transaction vs stats |
| S3 | SPL Search Reference: Event order functions (10.0) | https://help-preview.splunk.com/en/splunk-enterprise/spl-search-reference/10.0/statistical-and-charting-functions/event-order-functions | primer | diakses 2026-10-07 | Tinggi. Definisi first/last vs earliest/latest (domain help-preview) |
| S4 | Splunk Community: "Why are stats functions first and latest not returning the same" | https://community.splunk.com/t5/Splunk-Search/Why-are-stats-functions-first-and-latest-not-returning-the-same/td-p/472155 | komunitas | tanggal tidak tercatat | Rendah-sedang. Dikonfirmasi S3 |
| S5 | Splunk Community: "transaction vs stats commands", "Optimize transaction query", "Alternative of transaction" | https://community.splunk.com/t5/Splunk-Search/transaction-vs-stats-commands/td-p/9224 | komunitas | tanggal tidak tercatat | Sedang. Beberapa thread independen, dikonfirmasi S2 |
| S6 | SPL2 Search Reference: event order functions | https://help.splunk.com/en/splunk-enterprise/search/spl2-search-reference/statistical-and-charting-functions/event-order-functions | primer | tanggal tidak tercatat | Sedang. Dipakai hanya untuk catatan SPL2 |

**Catatan sumber:** klaim komunitas [S4][S5] hanya dipakai bila sejalan dengan dokumentasi [S2][S3]. Penjelasan bahwa `stats` berjalan terdistribusi di indexer sedangkan `transaction` dikerjakan di search head berasal dari panduan umum [S2]; rincian eksekusinya bisa dicek lewat Job Inspector di lab.
