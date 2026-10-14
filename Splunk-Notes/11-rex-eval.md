---
day: 11
title: 'rex dan eval: ekstraksi field saat search dan fungsi eval yang sering dipakai untuk keamanan'
researched_on: 2026-10-07
versions_checked: Splunk Enterprise SPL Search Reference 10.2 (rex, eval, Evaluation functions; halaman diperbarui Jan 2026); Splunk Enterprise terbaru 10.6
---

# Day 11: rex dan eval untuk ekstraksi field dan normalisasi

Cakupan: ekstraksi field ad hoc dengan `rex` dan pembuatan field, flag, serta skor triage dengan `eval` dan fungsi evaluasinya.

## Ide inti

Data yang belum ter-parse rapi bukan alasan menunda investigasi. `rex` dan `eval` adalah dua alat yang membuat analyst bisa memparsing dan menormalkan data di dalam search, saat itu juga, tanpa menunggu admin mengubah konfigurasi. `rex` membuat field baru dari teks yang belum punya field, atau mengganti isi teks lewat mode sed. `eval` membuat field turunan dari field yang sudah ada, mulai dari normalisasi huruf dan decoding sampai flag dan skor triage. Dasar SPL dan `eval` sederhana sudah ada di Day 02; Day ini memperdalam keduanya sampai ke pola kerja "ekstrak, normalisasi, lalu beri skor".

Analoginya: field extraction search-time adalah parser yang dijalankan saat log dibaca, bukan saat log disimpan. `rex` adalah versi sekali pakai dari parser itu, dan `eval` adalah kolom formula di spreadsheet yang dihitung ulang setiap kali tabelnya dibuka. Batas analoginya: keduanya tidak mengubah data yang tersimpan di index, sehingga kesalahan regex atau rumus bisa diperbaiki kapan saja tanpa re-ingest, tetapi hasilnya juga hanya ada di search yang menuliskannya. Logika yang dipakai banyak dashboard dan detection tidak boleh bergantung pada `rex` yang disalin ulang di setiap search.

**Kapan relevan:** investigasi ad hoc atas log yang field-nya belum lengkap, prototipe extraction sebelum diusulkan menjadi knowledge object, normalisasi nilai antar sourcetype, dan pembuatan field turunan seperti skor, kategori, atau flag.
**Kapan bukan jawaban:** extraction yang sama dipakai puluhan dashboard dan detection. Jadikan field extraction permanen agar konsisten dan mudah dirawat; ini kembali di topik CIM (Day 23, 24, dan 26). Skor dari `eval` juga bukan deteksi final, hanya alat triage.

## 1. Konsep inti

### 1.1 rex: dua mode

Sintaks [S1]:

```
rex [field=<field>] "<regex>" [max_match=<int>] [offset_field=<string>]
rex [field=<field>] mode=sed "<sed-expression>"
```

- **Mode ekstraksi:** regex PCRE dengan named capture group `(?<nama>pola)`. Setiap grup menjadi field baru [S1].
- `field=`: field sumber. Default `_raw` [S1]. Mengarahkan `rex` ke field yang lebih kecil (mis. `CommandLine`) lebih cepat dan lebih tepat.
- `max_match`: berapa kali pola dicocokkan. Default 1. `max_match=0` berarti tidak terbatas dan menghasilkan field multivalue [S1]. Berguna untuk mengambil semua IP atau URL dalam satu event.
- `offset_field`: menyimpan posisi karakter hasil match. Jarang dipakai di keamanan.
- **Mode sed:** `s/<regex>/<pengganti>/<flag>` untuk substitusi (flag `g` = semua kemunculan) dan `y/<set1>/<set2>/` untuk transliterasi karakter [S1]. Biasa dipakai untuk masking data sensitif atau normalisasi (membuang angka acak, GUID).

**`rex` vs `regex`:** `rex` mengekstrak atau mengganti nilai. Command `regex` hanya menyaring event yang cocok atau tidak cocok dengan pola, tanpa membuat field [S1].

**`rex` vs field extraction permanen:** praktisi di Splunk Community menjelaskan bahwa biaya regex per event kurang lebih sama. Bedanya, `rex` hanya membebani search yang memakainya, sedangkan extraction permanen berjalan di setiap search atas sourcetype itu, dengan sedikit keuntungan caching di lingkungan terdistribusi [S4]. `[komunitas]` Tips performa dari thread yang sama sejalan dengan prinsip regex umum:
- Hindari `.*` di awal/akhir.
- Gunakan quantifier non-greedy bila perlu.
- Jangkarkan pola pada teks tetap yang kamu tahu.
- Hindari case-insensitive kecuali perlu.

### 1.2 eval: dasar yang sering salah

Sintaks: `eval <field>=<ekspresi>[, <field>=<ekspresi>]...`. Ekspresi dievaluasi dari kiri ke kanan, jadi field yang dibuat di assignment pertama bisa dipakai di assignment berikutnya dalam `eval` yang sama [S2].

Aturan kutip (sumber kesalahan nomor satu) [S2]:
- Kutip ganda `"..."` = string literal.
- Kutip tunggal `'...'` = nama field. Wajib dipakai bila nama field mengandung karakter selain huruf, angka, dan underscore, mis. `'Account Name'` atau `'Processes.process'`.
- Akibatnya: `eval x="user"` mengisi x dengan teks `user`, sedangkan `eval x='user'` mengisi x dengan nilai field `user`.

Hal lain [S2]:
- Operator: aritmatika `+ - * / %`, konkatenasi string `.`, perbandingan dan boolean (`AND OR NOT XOR`), serta `LIKE` (`%` = banyak karakter, `_` = satu karakter).
- Pembagian dengan nol menghasilkan null, bukan error.
- Jika nama field sudah ada, nilainya ditimpa. Hati-hati menimpa field bawaan atau CIM.
- Nilai boolean tidak bisa langsung disimpan ke field. Gunakan `if()` atau `tostring()`.
- `eval` juga dipakai di `where`, `fieldformat`, dan sebagai ekspresi di command lain, mis. `stats count(eval(...))` [S3].

### 1.3 Fungsi eval yang paling sering dipakai analyst

Dokumentasi 10.2 mengelompokkan fungsi ke beberapa kategori. Selain kategori klasik, sekarang ada kategori JSON (`json_extract`, `json_keys`, `json_set`, `json_valid`, dll.) dan fungsi `lookup()` untuk lookup CSV dari dalam eval [S3].

| Kebutuhan keamanan | Fungsi | Contoh |
|---|---|---|
| Kategori/skor bertingkat | `case(c1,v1, c2,v2, ..., true(),default)` | Tingkat risiko berdasarkan beberapa kondisi |
| Kondisi tunggal | `if(cond, a, b)` | Flag internal/eksternal |
| Ambil nilai non-null pertama | `coalesce(a,b,c)` | Gabungkan `src_ip`, `Source_Network_Address`, `clientip` |
| IP dalam subnet | `cidrmatch("10.0.0.0/8", ip)` | Bedakan trafik internal |
| Regex sebagai kondisi | `match(field, "regex")` | Command line mengandung `-enc` |
| Wildcard sederhana | `like(field, "%pattern%")` | Path mengandung `\Temp\` |
| Keanggotaan daftar | `in(field, "a","b")` | Proses LOLBin tertentu |
| Panjang | `len(field)` | Command line yang sangat panjang |
| Normalisasi | `lower()`, `upper()`, `trim()`, `replace()`, `substr()` | Bandingkan nama proses tanpa beda huruf besar/kecil |
| Decode URL | `urldecode()` | Payload di parameter URL |
| Multivalue | `split()`, `mvindex()`, `mvcount()`, `mvjoin()`, `mvfilter()` | Ambil domain dari FQDN, hitung argumen |
| Waktu | `now()`, `relative_time()`, `strftime()`, `strptime()` | Jam kerja vs di luar jam kerja |
| Hash | `md5()`, `sha1()`, `sha256()`, `sha512()` | Hash dari string untuk pseudonimisasi |
| Null | `isnull()`, `isnotnull()`, `null()`, `nullif()` | Deteksi field yang tidak terisi |

Semua fungsi di atas tercantum di referensi Evaluation functions 10.2 [S3]. Fungsi seperti entropi (Shannon) tidak ada sebagai fungsi eval bawaan. Biasanya fungsi itu datang dari app tambahan seperti URL Toolbox (macro `ut_shannon`); pastikan app dan macro itu terpasang di instance-mu sebelum memakainya.

### 1.4 Enterprise vs ES

`rex`, `regex`, `eval`, dan semua fungsi di atas adalah fitur inti Splunk Enterprise. ES tidak menambah fungsi eval, tetapi detection ES memakainya secara luas, misalnya `eval` untuk membangun field `risk_score` atau pesan dinamis (Day 35-36).

## 2. Contoh SPL dan langkah di ES

> Keluaran berlabel ilustrasi. Asumsi data: BOTS v1 (`index=botsv1`). Sysmon di sourcetype `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` dengan field `CommandLine`, `Image`, `ParentImage`, `host`; web di `stream:http` dengan field `src_ip`, `dest_ip`, `uri`, `http_user_agent`, `site`. Cek semua nama field di lab-mu.

### 2.1 rex: ekstrak blob PowerShell -EncodedCommand

**Tujuan:** menemukan PowerShell dengan argumen terenkode dan mengambil blob-nya untuk dianalisis.

```
index=botsv1 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*\\powershell.exe"
| rex field=CommandLine "(?i)\s[-/](?:ec|e[a-z]*)\s+(?<enc_blob>[A-Za-z0-9+/=]{20,})"
| where isnotnull(enc_blob)
| eval blob_len=len(enc_blob)
| stats count values(host) AS hosts max(blob_len) AS max_len BY ParentImage
```

| Bagian | Penjelasan |
|---|---|
| `field=CommandLine` | Regex hanya dijalankan pada command line, bukan `_raw`, jadi lebih cepat dan tidak salah cocok di tempat lain |
| `(?i)` | Case-insensitive, karena PowerShell menerima variasi huruf besar/kecil |
| `[-/](?:ec\|e[a-z]*)` | PowerShell menerima awalan parameter dengan `-` atau `/` dan menerima singkatan apa pun dari `-EncodedCommand` (`-e`, `-en`, `-enc`, dan seterusnya), plus alias `-ec`. Pola `e[a-z]*` sengaja longgar; syarat blob base64 minimal 20 karakter yang menyaring parameter lain seperti `-ExecutionPolicy Bypass`. Cek perilaku singkatan di versi PowerShell lab-mu |
| `(?<enc_blob>[A-Za-z0-9+/=]{20,})` | Named group: karakter base64, minimal 20 |
| `where isnotnull(enc_blob)` | Hanya event yang cocok |
| `eval blob_len=len(enc_blob)` | Panjang blob sebagai fitur tambahan |
| `stats ... BY ParentImage` | Siapa yang meluncurkan PowerShell terenkode, konteks terpenting |

Keluaran ilustrasi:

```
ParentImage                                   count  hosts        max_len
C:\Windows\System32\cmd.exe                   3      we8105desk   1844
C:\Program Files\SomeAgent\agent.exe          120    (banyak)     212
```

**Cara membaca hasil:** baris kedua (agen manajemen, banyak host, blob pendek) kemungkinan jinak, tetapi verifikasi dulu. Baris pertama layak diinvestigasi. Langkah lanjut di luar Splunk: dekode blob (base64, UTF-16LE) di workstation analisis, bukan dengan menjalankannya.
**Kapan gagal:** command line terpotong; parameter memakai karakter en dash Unicode (PowerShell menerimanya sebagai awalan parameter, tetapi regex di atas hanya menangkap `-` dan `/`); argumen dipisah tanda kutip.

### 2.2 rex max_match=0 dan mode=sed

Ambil semua IP dari satu field teks (mis. pesan log aplikasi):

```
... | rex field=message max_match=0 "(?<ip_list>\b(?:\d{1,3}\.){3}\d{1,3}\b)"
| eval ip_count=mvcount(ip_list)
```

- `max_match=0`: semua kemunculan, sehingga `ip_list` menjadi multivalue [S1].
- `mvcount()`: berapa IP yang ditemukan.
- Regex IP ini sederhana dan juga cocok dengan `999.1.1.1`. Untuk validasi, saring hasilnya lagi.

Masking untuk berbagi hasil (mis. ke vendor) dengan mode sed:

```
... | rex field=user mode=sed "s/^(.).*(.)$/\1***\2/"
| rex field=_raw mode=sed "s/password=\S+/password=REDACTED/g"
```

- Baris 1 menyamarkan nama user menjadi huruf pertama dan terakhir.
- Baris 2 menghapus nilai password di raw event pada hasil tampilan. Data asli di index tidak berubah.

### 2.3 eval: normalisasi dan skor risiko sederhana

**Tujuan:** memberi skor heuristik pada request web untuk triage. Ini bukan deteksi final.

```
index=botsv1 sourcetype=stream:http
| eval src=coalesce(src_ip, clientip),
       uri_dec=lower(urldecode(uri)),
       ua=lower(http_user_agent),
       is_internal_src=if(cidrmatch("192.168.0.0/16", src), 1, 0),
       sqli=if(match(uri_dec, "(union\s+select|or\s+1=1|sleep\()"), 1, 0),
       traversal=if(like(uri_dec, "%../%"), 1, 0),
       scanner_ua=if(match(ua, "(sqlmap|nikto|acunetix|nmap)"), 1, 0),
       long_uri=if(len(uri_dec) > 500, 1, 0),
       score = sqli*40 + traversal*30 + scanner_ua*20 + long_uri*10,
       level = case(score>=60, "high", score>=30, "medium", score>0, "low", true(), "none")
| where score > 0
| stats count max(score) AS max_score values(level) AS levels values(site) AS sites BY src
| sort - max_score
```

Baris demi baris:
- `coalesce(src_ip, clientip)`: satu field sumber, apa pun nama aslinya di sourcetype berbeda.
- `lower(urldecode(uri))`: decode lalu huruf kecil. Penyerang meng-encode payload, jadi pencocokan pada nilai yang belum di-decode akan gagal.
- `cidrmatch`: tandai sumber internal. Subnet ini asumsi untuk BOTS, jadi sesuaikan.
- `match(...)` dan `like(...)`: flag pola. Pola sengaja sederhana dan tidak lengkap.
- `score = ...`: bobot ilustratif. Assignment ini memakai field yang dibuat di `eval` yang sama, sesuai urutan kiri ke kanan [S2].
- `case(..., true(), "none")`: `true()` adalah kondisi default terakhir.

Keluaran ilustrasi:

```
src             count  max_score  levels        sites
40.80.148.42    9123   60         high medium   imreallynotbatman.com
```

**Cara membaca hasil:** skor tinggi dengan user-agent scanner dan volume besar adalah pola pemindaian/serangan web. Langkah lanjut: lihat request mana yang mendapat respon 200, dan apakah ada upload (Day 20 review).
**Kapan gagal:** field `uri` tidak menyertakan query string (tergantung sumber); user-agent dipalsukan; skor ad hoc tidak dikalibrasi. Jangan pakai sebagai deteksi produksi tanpa tuning.

### 2.4 eval waktu: di luar jam kerja

```
... | eval hour=tonumber(strftime(_time, "%H")), dow=strftime(_time, "%a"),
       off_hours=if(hour<7 OR hour>=19 OR in(dow, "Sat", "Sun"), 1, 0)
```

- `strftime(_time, "%H")` mengikuti zona waktu di preferensi akun Splunk-mu, bukan zona waktu host asal. Ini jebakan saat korelasi lintas negara.
- `in(dow, "Sat", "Sun")` adalah fungsi eval yang aman dipakai di `eval` dan `where`. Operator `IN (...)` paling umum dipakai di command `search`; di dalam ekspresi eval, catatan ini konsisten memakai fungsi `in()` agar tidak bergantung versi.

### 2.5 Langkah di ES (generik)

- Detection dan dashboard ES memakai field CIM. Jika log sumbermu tidak ter-normalisasi, `rex`/`eval` di search ad hoc adalah diagnosis, bukan solusi. Solusinya extraction dan alias di add-on (Day 23, 24, dan 26).
- Di ES, `eval` sering dipakai untuk membuat field yang dibaca framework risiko, misalnya pesan dinamis atau `risk_object`. Detailnya di Day 35.

## 3. Lab praktik

1. Jalankan bagian 2.1 di BOTS v1. Jika tidak ada PowerShell terenkode, buat sendiri di VM Windows lab yang terisolasi: jalankan perintah jinak terenkode, mis. encode `Get-Date` dalam UTF-16LE base64, lalu `powershell -enc <blob>`. Tunggu Sysmon terkirim, lalu ulangi query.
2. Ubah bagian 2.1 dengan menghapus `field=CommandLine` (artinya `rex` pada `_raw`). Bandingkan durasi job dan apakah ada match palsu.
3. Jalankan bagian 2.3. Catat 3 `src` teratas dan alasan skornya.
4. Uji aturan kutip: jalankan `| makeresults | eval user="alice", a="user", b='user'` lalu bandingkan `a` dan `b`. (`makeresults` dibahas besok.)
5. Jalankan bagian 2.2 masking pada field user di data apa pun. Pastikan data asli tidak berubah dengan menjalankan search tanpa `rex`.
6. Pilih satu sourcetype di lab yang field-nya kurang lengkap. Prototipe extraction dengan `rex`, lalu tulis usulan extraction permanen (regex + nama field) untuk admin/dirimu sendiri.

**Hasil yang sebaiknya tersimpan:**
- Ada perbandingan durasi `rex field=` vs `_raw`.
- Bisa menjelaskan hasil langkah 4 (kutip tunggal vs ganda).
- Skor bagian 2.3 dihasilkan dan ditafsirkan dengan penjelasan jinak/berbahaya.
- Usulan extraction permanen tertulis.

**Variasi tantangan:** gunakan `split()` dan `mvindex()` untuk mengambil registered domain sederhana (dua label terakhir) dari field `site`, lalu hitung domain dengan jumlah subdomain unik terbanyak. Jelaskan kenapa metode "dua label terakhir" salah untuk domain seperti `.co.id`, cek pendekatan yang lebih benar, mis. memakai daftar public suffix lewat app.

## 4. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| `rex` tidak membuat field | Regex tidak cocok; field sumber salah; escape backslash | Uji regex di contoh event; ingat `\\` untuk backslash literal di string SPL |
| Field hasil eval berisi teks nama field | Memakai kutip ganda untuk nama field | Pakai kutip tunggal untuk nama field [S2] |
| Hasil eval kosong | Salah satu input null (operasi dengan null menghasilkan null) | `coalesce()` atau `isnull()` dulu; cek nama field |
| `rex` lambat | Regex pada `_raw` dengan `.*` di awal; data besar | `field=`, jangkar teks tetap, filter event lebih dulu [S4] |
| Ekstraksi hanya ambil satu nilai | `max_match` default 1 | `max_match=0` [S1] |
| Masking sed "tidak menyimpan" | Sed di `rex` hanya mengubah hasil search | Untuk masking saat ingest perlu konfigurasi admin (SEDCMD), perlu dicek |

## 5. Kesalahan umum dan jebakan

- Kutip tunggal vs ganda tertukar [S2]. Ini kesalahan `eval` paling umum.
- `rex` pada `_raw` padahal field sumber sudah ada. Lebih lambat dan rawan match palsu [S1][S4].
- Mencocokkan payload tanpa `urldecode`/`lower`. Penyerang memanfaatkan encoding dan huruf besar/kecil.
- Menimpa field CIM dengan eval (mis. `eval user=...`). Dashboard atau detection lain bisa ikut kacau di search yang sama. Pakai nama baru.
- Skor ad hoc dianggap deteksi. Itu alat triage. Kalibrasi diperlukan.
- `[komunitas]` Rekomendasi "rex untuk ad hoc, extraction permanen untuk pemakaian berulang" muncul di thread Splunk Community "rex vs extraction field" [S4]. Ini sejalan dengan logika biaya. Klaim tambahan di thread itu soal caching hasil extraction belum terkonfirmasi, jadi jangan dipakai sebagai alasan.

## 6. Catatan terkini

- Referensi Evaluation functions 10.2 (diperbarui Januari 2026) memisahkan kategori JSON functions dan fungsi `lookup()` dalam eval [S3]. Keduanya relevan untuk log cloud berformat JSON (AWS, Azure, Okta) yang banyak dibahas di Day 27.
- Splunk menerbitkan "Compatibility Quick Reference for SPL2 evaluation functions" hingga versi 10.6 [S5]. Beberapa fungsi berbeda nama/perilaku di SPL2. Untuk ujian dan ES, acuannya SPL klasik.

## 7. Cheat sheet

```
rex [field=F] "(?<name>regex)" [max_match=0 -> multivalue]      default field=_raw (lambat)
rex [field=F] mode=sed "s/regex/ganti/g" | "y/abc/xyz/"          hanya mengubah HASIL
regex F="pola"   -> hanya filter, tidak buat field

eval a=..., b=f(a)        kiri->kanan ; "..." = string ; '...' = nama field ; /0 -> null ; nama sama -> timpa
case(c1,v1,...,true(),def)  if(c,a,b)  coalesce(a,b)  cidrmatch("cidr",ip)  match(f,"re")  like(f,"%x%")  in(f,"a","b")
len lower upper trim replace substr urldecode | split mvindex mvcount mvjoin mvfilter
now() relative_time(now(),"-24h") strftime(_time,"%H") strptime(s,fmt) | md5 sha256 | isnull isnotnull
json_extract json_keys ... (kategori JSON, 10.x) | lookup() (CSV)
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Kamu menulis `| eval akun="user"` dan hasilnya setiap baris berisi teks `user`, bukan nama akunnya. Apa yang salah, dan apa bedanya dengan `| eval akun='user'`?

<details><summary>Jawaban</summary>

Kutip ganda di `eval` berarti string literal, jadi `akun="user"` mengisi field dengan teks `user`. Kutip tunggal berarti nama field, jadi `akun='user'` mengisi field dengan nilai field `user`. Kutip tunggal wajib dipakai bila nama field memuat karakter selain huruf, angka, dan underscore, misalnya `'Account Name'` atau `'Processes.process'`. Ini kesalahan `eval` yang paling sering terjadi, dan gejalanya mudah dikenali: seluruh kolom berisi teks yang sama. Lihat bagian 1.2.

</details>

**2. Skenario keputusan.** Sebuah regex untuk mengambil blob base64 dari command line PowerShell sudah terbukti berguna dan kini dipakai di satu dashboard dan dua alert terjadwal. Langkah mana yang paling tepat?

- A. Salin `rex` yang sama ke setiap dashboard dan alert supaya tidak bergantung pada konfigurasi orang lain.
- B. Usulkan extraction permanen dengan nama field yang sama, lalu ganti `rex` di dashboard dan alert dengan field itu.
- C. Hapus `rex` dan ganti dengan `regex` supaya lebih murah.

<details><summary>Jawaban</summary>

B. Biaya regex per event kurang lebih sama, bedanya `rex` hanya membebani search yang memakainya sedangkan extraction permanen berjalan di setiap search atas sourcetype itu. Yang menentukan di sini bukan biaya, tetapi perawatan: logika yang dipakai banyak tempat harus punya satu definisi, supaya perbaikan regex tidak perlu dikejar ke lima tempat. A membuat lima salinan yang pasti akan berbeda isi suatu hari. C salah paham fungsi: `regex` hanya menyaring event yang cocok, tidak membuat field, jadi dashboard dan alert-nya akan kehilangan field yang dibutuhkan. Lihat bagian 1.1.

</details>

**3. Pertanyaan jebakan.** "Aku sudah menjalankan `rex field=_raw mode=sed "s/password=\S+/password=REDACTED/g"`, jadi password di index itu sudah tersensor." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Mode sed di `rex` hanya mengubah hasil search yang sedang kamu lihat, bukan data yang tersimpan di index. Gunanya untuk membagikan hasil ke pihak lain tanpa ikut membagikan nilai sensitifnya. Masking saat ingest adalah konfigurasi di sisi admin, dan itu perlu dicek karena menyangkut data yang sudah masuk. Lihat bagian 1.1, 2.2, dan 4.

</details>

**4. Pertanyaan jebakan.** Satu pesan log memuat tiga alamat IP, tetapi `| rex field=message "(?<ip>\b(?:\d{1,3}\.){3}\d{1,3}\b)"` hanya menghasilkan satu nilai. Kenapa, dan apa akibatnya untuk pencarian payload yang di-encode?

<details><summary>Jawaban</summary>

`max_match` default-nya 1, jadi hanya kemunculan pertama yang diambil; `max_match=0` berarti tanpa batas dan menghasilkan field multivalue yang bisa dihitung dengan `mvcount()`. Jebakan serupa pada pencocokan payload adalah encoding dan huruf besar kecil: pencocokan harus dilakukan setelah `urldecode()` dan `lower()`, karena penyerang memanfaatkan keduanya. Keduanya satu pola kesalahan yang sama, yaitu menguji regex hanya dengan satu kasus positif yang rapi. Lihat bagian 1.1, 2.2, dan 2.3.

</details>

**5. Interview question (English).** "When would you use rex in a search instead of asking for a permanent field extraction?"

<details><summary>Sample answer</summary>

"I use rex when I need an answer now and the field doesn't exist yet: a new log source, a command line that packs several things into one string, or a URL I have to decode before I can match on it. It costs about the same per event as a permanent extraction, but it only loads the search I run, and I can fix a bad pattern immediately without touching anyone's configuration. The moment the same pattern starts showing up in dashboards or scheduled detections, I treat that as a signal to ask for a permanent extraction with a proper field name, because logic that lives in five copies will drift. I also point rex at the smallest field I can instead of _raw, anchor it on fixed text, and test it with negative cases, since a pattern that only ever saw one clean positive example is how detections quietly miss things."

What makes this answer strong: it separates the cost question from the maintenance question, shows awareness that ad hoc work should graduate into knowledge objects, and ends with concrete habits (field scoping, anchoring, negative test cases) rather than a general claim about regex.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | SPL Search Reference: rex (10.2) | https://help.splunk.com/en/splunk-enterprise/spl-search-reference/10.2/search-commands/rex | primer | diakses 2026-10-07 | Tinggi |
| S2 | SPL Search Reference: eval (10.2) | https://help.splunk.com/en/splunk-enterprise/spl-search-reference/10.2/search-commands/eval | primer | diakses 2026-10-07 | Tinggi. Aturan kutip, operator, null |
| S3 | SPL Search Reference: Evaluation functions (10.2) | https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.2/evaluation-functions | primer | diperbarui Jan 2026; diakses 2026-10-07 | Tinggi. Kategori dan fungsi |
| S4 | Splunk Community: "rex vs extraction field" | https://community.splunk.com/t5/Splunk-Search/rex-vs-extraction-field/m-p/102639 | komunitas | tanggal tidak tercatat (thread lama) | Rendah-sedang |
| S5 | Compatibility Quick Reference for SPL2 evaluation functions (10.6) | https://help.splunk.com/en/splunk-enterprise/process-data-at-the-edge/quick-reference-for-spl2/10.6/compatibility-quick-reference-for-spl2-evaluation-functions | primer | tanggal tidak tercatat | Sedang. Hanya untuk catatan SPL2 |

**Catatan sumber:** daftar fungsi di bagian 1 mencakup fungsi yang paling sering dipakai untuk keamanan, bukan seluruh referensi Evaluation functions [S3]; fungsi yang jarang dipakai cek langsung di referensi versi-mu. Aturan singkatan parameter PowerShell (`-e`, `-enc`, `-ec`) mengikuti perilaku PowerShell yang umum dikenal dan sebaiknya diuji dengan `makeresults` sebelum dipakai di detection. Nama macro entropi URL Toolbox bisa berbeda antar versi app.
