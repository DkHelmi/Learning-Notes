---
day: 07
title: 'IOC dan pengayaan: siklus hidup indikator, konteks, dan dasar STIX 2.1 serta TAXII 2.1'
researched_on: 2026-10-10
versions_checked: 'OASIS STIX 2.1 dan TAXII 2.1 (OASIS Standard, 10 Juni 2021); rujukan Day 03-05'
---

# Day 07: IOC, pengayaan, dan STIX/TAXII

Cakupan: apa itu IOC dan bagaimana mengelolanya sepanjang siklus hidup, cara memperkaya indikator dengan konteks secara sah, dan cara menyatakan serta memindahkan intelijen terstruktur dengan STIX 2.1 dan TAXII 2.1.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- menjelaskan apa itu IOC, jenis-jenisnya, dan siklus hidupnya dari observasi sampai pensiun.
- membedakan IOC mentah dari IOC yang kaya konteks dan menjelaskan kenapa konteks menentukan nilai.
- melakukan pengayaan (enrichment) IOC lewat sumber sah tanpa membocorkan data.
- membaca dan menulis objek STIX 2.1 inti (Indicator, Relationship, Malware, Attack Pattern) beserta pola STIX patterning sederhana.
- menjelaskan endpoint dan alur TAXII 2.1, termasuk cara klien menarik objek baru secara bertahap.
- menghubungkan IOC dan STIX ke Pyramid of Pain dan ke operasionalisasi (Day 10).

## 2. Konteks singkat

IOC (Indicator of Compromise) adalah artefak teknis yang menandai kemungkinan kompromi: hash, IP, domain, URL, alamat email pengirim, atau artefak di host. IOC adalah bentuk intelijen paling konkret dan paling mudah dipakai mesin, tetapi juga paling rapuh. Penyerang bisa mengganti IP dalam hitungan menit dan mengompilasi ulang file sehingga hash-nya berubah. Itulah posisi IOC di dasar Pyramid of Pain (Day 04).

Nilai IOC ada pada konteksnya. Tanpa tahu dari mana indikator itu berasal, kapan terakhir terlihat, terkait kampanye apa, dan seberapa yakin sumbernya, sebuah IP hanyalah angka. Pengayaan menambahkan konteks itu, dan manajemen siklus hidup memastikan indikator tidak dipakai setelah basi.

Untuk berbagi antar organisasi, industri memakai dua standar OASIS: STIX untuk menyatakan intelijen, TAXII untuk memindahkannya. Platform CTI (Day 08) dan banyak feed memakai keduanya, jadi kamu perlu bisa membaca objek STIX mentah saat feed bermasalah.

**Kapan dipakai:** mengelola indikator dari insiden dan feed, berbagi intelijen antar organisasi, mengintegrasikan feed ke platform dan SIEM.

**Kapan terbatas:** IOC atomik cepat basi dan mudah dielak; STIX terasa berat bila kebutuhanmu hanya daftar sepuluh domain untuk satu blokir sementara.

## 3. Konsep inti

### 3.1 Jenis IOC dan daya tahannya

| Jenis | Contoh (defang) | Daya tahan | Catatan |
|---|---|---|---|
| Hash file | sha256 `<hash-fiktif>` | Sangat rendah | Satu bit berubah, hash berubah. Berguna untuk file yang sama persis |
| IP address | 203.0.113[.]50 | Rendah | Sering berganti; bisa milik hosting bersama atau CDN |
| Domain | bad-logistics[.]example | Rendah-sedang | Butuh biaya dan waktu untuk mendaftar dan menyiapkan yang baru |
| URL | hxxps://bad-logistics[.]example/inv/a1 | Rendah | Path mudah diubah; domainnya lebih berharga |
| Email pengirim | billing@bad-logistics[.]example | Rendah | Berguna untuk filter email dan pencarian retroaktif |
| Artefak host | nama service, nama mutex, path persisten | Sedang | Lebih tahan, tetapi bisa dikonfigurasi ulang oleh operator |
| Artefak jaringan | user-agent unik, pola URI, sertifikat TLS | Sedang | Sering dipakai ulang lintas infrastruktur |

Urutan ini sejajar dengan Pyramid of Pain (Day 04): makin ke bawah tabel, makin mahal bagi penyerang untuk menggantinya. Di puncak ada TTP, yang bukan IOC atomik.

Karena itu jangan menilai feed dari jumlah hash-nya.

### 3.2 IOC, observable, Indicator, dan TTP

Empat istilah ini sering dicampur, dan STIX memisahkannya dengan tegas.

- **Observable** adalah fakta mentah yang teramati: domain ini ada, file dengan hash ini ada. Di STIX disebut SCO (STIX Cyber-observable Object), misalnya `domain-name` atau `file`. Observable tidak berkata apa-apa tentang baik atau buruk.
- **IOC** dalam percakapan sehari-hari berarti observable yang dicurigai terkait aktivitas jahat.
- **Indicator** di STIX adalah objek terpisah yang berisi pola deteksi (misalnya "domain sama dengan X"), rentang validitas, dan konteks. Indicator adalah klaim: "bila kamu melihat pola ini, kemungkinan ada aktivitas jahat".
- **TTP** dinyatakan sebagai Attack Pattern (memetakan ke ATT&CK), bukan sebagai Indicator.

Manfaat praktisnya: bila domain ternyata milik layanan sah, kamu mencabut Indicator-nya tanpa menghapus fakta bahwa domain itu pernah teramati.

### 3.3 Siklus hidup IOC

IOC punya umur. Siklus yang sehat punya enam tahap:

1. **Observasi:** IOC muncul dari insiden internal, feed, laporan, atau mitra.
2. **Validasi:** apakah benar berbahaya? Cek apakah milik layanan sah, CDN, resolver publik, atau alamat privat. Cek apakah sumber menyebut konteks.
3. **Pengayaan:** tambah konteks (bagian 3.4).
4. **Operasionalisasi:** pakai untuk deteksi, blokir, atau pencarian retroaktif (Day 10).
5. **Peninjauan:** apakah masih menghasilkan hit? Hit-nya true positive atau false positive? Apakah ada laporan baru yang mengubah penilaian?
6. **Pensiun (expiry):** indikator dicabut dari daftar aktif, tetapi tetap disimpan untuk keperluan pencarian historis.

Umur wajar berbeda per jenis. Tidak ada angka baku dari standar, jadi tetapkan kebijakan sendiri dan tulis alasannya. Titik awal yang sering dipakai praktisi:

| Jenis | Umur awal yang masuk akal | Alasan |
|---|---|---|
| IP | 7-30 hari | Infrastruktur cepat berpindah dan sering dipakai ulang pihak lain |
| URL | 30 hari | Path cepat berubah |
| Domain | 90 hari, tinjau lalu perpanjang bila masih aktif | Lebih stabil, tetapi bisa diambil alih atau di-sinkhole |
| Hash | Panjang (6-12 bulan) | Hash file jahat tidak akan menjadi sah; risikonya hanya tidak relevan lagi |

Tanpa expiry, daftar indikator membengkak; setelah setahun sebagian besar IP di dalamnya sudah berpindah tangan dan blokirnya mengenai layanan yang tidak bersalah.

### 3.4 Pengayaan (enrichment)

Pengayaan menambahkan konteks ke IOC mentah agar bisa dinilai dan ditindaklanjuti. Jenis pengayaan yang umum:

| Jenis | Pertanyaan yang dijawab | Contoh hasil |
|---|---|---|
| Passive DNS | Domain ini pernah resolve ke IP apa, sejak kapan? | Domain resolve ke tiga IP berbeda dalam dua minggu |
| WHOIS dan RDAP | Kapan didaftarkan, lewat registrar apa? | Didaftarkan 5 hari sebelum kampanye |
| ASN dan geolokasi | Di jaringan siapa IP ini berada? | Hosting VPS murah, bukan ISP rumahan |
| Sertifikat TLS | Sertifikat apa yang dipakai, dipakai di host mana lagi? | Sertifikat self-signed yang sama di empat IP lain |
| Reputasi | Apakah sudah dilaporkan pihak lain? | Dua feed komunitas menandai sebagai C2 |
| Kaitan | Terkait kampanye, aktor, atau laporan apa? | Disebut di laporan vendor tentang sektor logistik |
| Sighting internal | Apakah pernah terlihat di log kita? | 3 host query domain ini minggu lalu |

Sighting internal paling sering dilupakan: IOC yang belum pernah muncul di lingkunganmu bernilai sebagai deteksi preventif, sedangkan yang sudah muncul di log berarti ada investigasi yang perlu dibuka.

Pengayaan harus sah dan aman:

- Pakai sumber dan API sesuai ToS dan lisensinya (Day 05).
- Jangan mengunggah file, email, atau dokumen dari insiden ke layanan publik. Sandbox dan layanan pemindaian publik bisa membagikan sampel ke pelanggan lain, dan penyerang ikut memantau apakah sampel mereka sudah terunggah. Cari berdasarkan hash, bukan dengan mengunggah file.
- Query aktif ke infrastruktur penyerang (membuka URL, melakukan scan) bisa memberi tahu penyerang bahwa mereka sedang diselidiki. Utamakan sumber pasif seperti passive DNS dan riwayat sertifikat.
- Defang IOC saat menulis di tiket, chat, dan dokumen agar tidak diklik atau dirender sebagai tautan.

Konvensi defang yang umum: `.` menjadi `[.]` dan `http` menjadi `hxxp`. Pastikan alat ingestion-mu me-refang nilai sebelum mencocokkan.

### 3.5 STIX 2.1: bahasa intelijen

STIX (Structured Threat Information Expression) adalah bahasa dan format serialisasi JSON untuk menyatakan CTI secara terstruktur. STIX 2.1 menjadi OASIS Standard pada 10 Juni 2021 [S1]. Objeknya dibagi menjadi beberapa kelompok:

- **SDO (STIX Domain Object):** konsep intelijen tingkat tinggi. STIX 2.1 mendefinisikan 18 SDO: Attack Pattern, Campaign, Course of Action, Grouping, Identity, Indicator, Infrastructure, Intrusion Set, Location, Malware, Malware Analysis, Note, Observed Data, Opinion, Report, Threat Actor, Tool, dan Vulnerability.
- **SCO (STIX Cyber-observable Object):** nilai teknis mentah, misalnya `ipv4-addr`, `ipv6-addr`, `domain-name`, `url`, `file`, `email-addr`, `email-message`, `network-traffic`, `process`, `windows-registry-key`, `x509-certificate`, dan `autonomous-system`.
- **SRO (STIX Relationship Object):** dua jenis. `relationship` menghubungkan dua objek (misalnya Indicator `indicates` Malware), dan `sighting` menyatakan bahwa sesuatu terlihat di suatu tempat oleh suatu pihak.
- **Meta object:** `marking-definition` (misalnya TLP), `language-content`, dan `extension-definition`.

Properti umum yang ada di hampir semua objek: `type`, `spec_version` (bernilai `"2.1"`), `id` (format `<type>--<UUID>`), `created`, `modified`, dan opsional `created_by_ref`, `confidence`, `labels`, `object_marking_refs`, `external_references`, serta `revoked`.

Untuk Indicator, properti wajibnya adalah `type`, `spec_version`, `id`, `created`, `modified`, `pattern`, `pattern_type`, dan `valid_from`. `valid_until` opsional tetapi sebaiknya diisi karena itulah cara STIX menyatakan expiry. `confidence` bernilai 0-100.

Versi objek ditangani lewat `modified`: `id` sama dengan `modified` lebih baru berarti versi baru. Indicator yang salah dicabut lewat versi baru dengan `revoked: true` (contoh di bagian 4.3).

Relationship adalah kekuatan STIX. Contoh `relationship_type` yang sering dipakai: `indicates` (Indicator ke Malware, Campaign, atau Intrusion Set), `uses` (Intrusion Set ke Malware, Tool, atau Attack Pattern), `targets` (Campaign ke Identity, Location, atau Vulnerability), `attributed-to` (Campaign ke Intrusion Set, Intrusion Set ke Threat Actor), dan `based-on` (Indicator ke Observed Data). Dengan relationship, konsumen bisa menjawab "domain ini terkait aktor apa dan aktor itu memakai teknik apa", bukan hanya "domain ini jahat".

### 3.6 STIX patterning

Properti `pattern` di Indicator memakai bahasa pola STIX. Bentuk dasarnya adalah comparison expression di dalam kurung siku: `[<object-type>:<property> <operator> <nilai>]`.

| Pola | Arti |
|---|---|
| `[domain-name:value = 'bad-logistics.example']` | Domain persis sama |
| `[ipv4-addr:value = '203.0.113.50']` | IP persis sama |
| `[ipv4-addr:value ISSUBSET '203.0.113.0/24']` | IP berada di dalam subnet |
| `[file:hashes.'SHA-256' = '<hash>']` | Hash SHA-256 file |
| `[url:value LIKE 'https://bad-logistics.example/inv/%']` | URL dengan awalan tertentu |
| `[email-message:from_ref.value = 'billing@bad-logistics.example']` | Pengirim email |
| `[file:name = 'invoice.js' AND file:size < 5000]` | Dua syarat pada objek yang sama |
| `[a] FOLLOWEDBY [b] WITHIN 300 SECONDS` | Observasi b terjadi setelah a dalam lima menit |

Operator perbandingan yang tersedia antara lain `=`, `!=`, `>`, `<`, `IN`, `LIKE`, `MATCHES` (regex), `ISSUBSET`, dan `ISSUPERSET`. Observation expression bisa digabung dengan `AND`, `OR`, dan `FOLLOWEDBY`, lalu diberi qualifier seperti `WITHIN`, `REPEATS ... TIMES`, atau `START ... STOP`.

Di dalam pola, nilai ditulis tanpa defang karena pola dibaca mesin. Defang hanya berlaku untuk teks yang dibaca manusia.

`pattern_type` tidak harus `stix`. STIX 2.1 mengizinkan pola dalam bahasa lain, misalnya `sigma`, `snort`, `suricata`, atau `yara`, sehingga satu Indicator bisa membawa rule Sigma utuh. Ini berguna saat berbagi deteksi perilaku, bukan hanya nilai atomik.

### 3.7 TAXII 2.1: transport

TAXII (Trusted Automated Exchange of Intelligence Information) adalah protokol aplikasi berbasis HTTPS dan REST untuk bertukar CTI, dirancang untuk mengangkut STIX. TAXII 2.1 menjadi OASIS Standard pada 10 Juni 2021 [S2].

Struktur endpoint-nya:

| Endpoint | Metode | Fungsi |
|---|---|---|
| `/taxii2/` | GET | Discovery: daftar API Root yang tersedia |
| `{api-root}/` | GET | Informasi API Root (judul, versi yang didukung, ukuran maksimum konten) |
| `{api-root}/collections/` | GET | Daftar Collection yang bisa diakses |
| `{api-root}/collections/{id}/objects/` | GET, POST | Mengambil atau menambahkan objek STIX |
| `{api-root}/collections/{id}/objects/{object-id}/` | GET, DELETE | Satu objek tertentu |
| `{api-root}/collections/{id}/objects/{object-id}/versions/` | GET | Daftar versi satu objek |
| `{api-root}/collections/{id}/manifest/` | GET | Metadata objek (id, waktu ditambahkan, versi) tanpa isi penuh |
| `{api-root}/status/{status-id}/` | GET | Status proses POST yang asinkron |

Media type yang dipakai adalah `application/taxii+json;version=2.1` untuk respons TAXII dan `application/stix+json;version=2.1` untuk konten STIX.

Parameter filter yang paling sering dipakai:

- `added_after=<timestamp>` untuk menarik hanya objek yang ditambahkan setelah pengambilan terakhir. Ini inti dari polling inkremental.
- `match[type]=indicator,malware` untuk menyaring jenis objek.
- `match[id]=...` dan `match[version]=last|first|all|<timestamp>` untuk memilih objek dan versi.
- `limit` dan `next` untuk paging.

Nilai ganda di satu filter dipisah koma dan berlaku sebagai OR; filter yang berbeda berlaku sebagai AND.

Collection punya properti `can_read` dan `can_write`. Autentikasi tidak diatur rinci oleh TAXII; implementasi umumnya memakai HTTP Basic atau token di atas TLS.

Konsep Channel (model publish-subscribe) hanya dicadangkan namanya di TAXII 2.1 dan belum didefinisikan [S2]. Jadi di 2.1 semua pertukaran bersifat request-response: klien bertanya secara berkala, server menjawab.

### 3.8 IOC yang baik: paket, bukan nilai

IOC yang baik adalah paket: nilai (defang untuk manusia), jenis, sumber dan keandalannya (Admiralty, Day 03), kaitan, keyakinan, tanggal pertama dan terakhir terlihat, kedaluwarsa, dan TLP. Paket ini membuat konsumen bisa memilih tindakan: blokir, alert, atau pengayaan saja. Kualitas CTI teknis diukur dari kekayaan konteks, bukan jumlah IOC.

## 4. Contoh artefak intelijen

Semua contoh di bagian ini fiktif dan berupa keluaran ilustrasi. IOC di-defang di teks; di dalam pola STIX ditulis tanpa defang karena dibaca mesin. Objek STIX disederhanakan, tetapi properti wajibnya lengkap.

### 4.1 IOC mentah vs kaya konteks

```
MENTAH (kurang berguna):
  203.0.113.50
  bad-logistics.example

KAYA KONTEKS (fiktif, defang):
  indikator     : domain bad-logistics[.]example
  jenis         : domain-name
  sumber        : laporan vendor publik (keandalan B, kredibilitas 2)
  kaitan        : diduga kampanye ransomware sektor logistik (keyakinan sedang)
  pertama dilihat: 2026-10-01   terakhir dilihat: 2026-10-08
  kedaluwarsa   : 2027-01-08 (tinjau sebelum perpanjang)
  pengayaan     : didaftarkan 2026-09-26 ; resolve ke 203.0.113[.]50 (passive DNS) ;
                  ASN fiktif AS65000 (hosting VPS) ; sertifikat self-signed
  sighting      : 0 hit di DNS log 30 hari terakhir
  tindakan      : alert (bukan blokir) sampai keyakinan naik
  TLP           : TLP:AMBER
```

Cara membaca: tanggal registrasi lima hari sebelum observasi pertama dan hosting VPS adalah ciri infrastruktur yang disiapkan untuk kampanye, yang menaikkan keyakinan. Nol sighting berarti indikator ini dipakai sebagai deteksi preventif, bukan pemicu investigasi. Tindakan "alert, bukan blokir" dipilih karena sumbernya tunggal.

### 4.2 Bundle STIX dengan Indicator, Malware, dan Relationship

```json
{
  "type": "bundle",
  "id": "bundle--5d0092c5-5f74-4287-9642-33f4c354e56d",
  "objects": [
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
      "created": "2026-10-08T00:00:00.000Z",
      "modified": "2026-10-08T00:00:00.000Z",
      "name": "Domain C2 kampanye logistik (fiktif)",
      "indicator_types": ["malicious-activity"],
      "pattern": "[domain-name:value = 'bad-logistics.example']",
      "pattern_type": "stix",
      "valid_from": "2026-10-08T00:00:00.000Z",
      "valid_until": "2027-01-08T00:00:00.000Z",
      "confidence": 60,
      "object_marking_refs": ["marking-definition--<id-TLP-AMBER>"]
    },
    {
      "type": "malware",
      "spec_version": "2.1",
      "id": "malware--31b940d4-6f7f-459a-80ea-9c1f17b58abc",
      "created": "2026-10-08T00:00:00.000Z",
      "modified": "2026-10-08T00:00:00.000Z",
      "name": "ransomware-lab",
      "is_family": true,
      "malware_types": ["ransomware"]
    },
    {
      "type": "relationship",
      "spec_version": "2.1",
      "id": "relationship--44298a74-ba52-4f0c-87a3-1824e67d7fad",
      "created": "2026-10-08T00:00:00.000Z",
      "modified": "2026-10-08T00:00:00.000Z",
      "relationship_type": "indicates",
      "source_ref": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
      "target_ref": "malware--31b940d4-6f7f-459a-80ea-9c1f17b58abc"
    }
  ]
}
```

Cara membaca:

- `bundle` hanya pembungkus untuk transport dan tidak punya `spec_version`. Isinya tiga objek.
- `valid_until` menyatakan expiry. Konsumen yang patuh berhenti memakai Indicator ini setelah 8 Januari 2027.
- `confidence: 60` sesuai keyakinan sedang. Perhatikan bahwa skala 0-100 ini tidak otomatis setara dengan skala keyakinan internalmu; tulis pemetaannya di kebijakan tim.
- `is_family: true` berarti objek ini mewakili keluarga malware, bukan satu sampel.
- Relationship menghubungkan Indicator ke Malware lewat `id`. Bila salah satu `id` keliru satu karakter saja, relationship menggantung dan platform biasanya menolaknya atau menampilkannya tanpa target.
- `<id-TLP-AMBER>` sengaja tidak ditulis. Marking TLP 1.0 punya id tetap di spesifikasi STIX 2.1, sedangkan TLP 2.0 (termasuk TLP:AMBER+STRICT dan TLP:CLEAR) dinyatakan lewat marking definition tambahan yang diterbitkan terpisah. Cek id mana yang dipakai platform-mu sebelum menulis marking secara manual.

### 4.3 Revoke dan versi baru

Misalkan seminggu kemudian terbukti domain itu di-sinkhole oleh peneliti dan tidak lagi dikendalikan penyerang. Produsen menerbitkan versi baru Indicator dengan `id` yang sama:

```json
{
  "type": "indicator",
  "spec_version": "2.1",
  "id": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
  "created": "2026-10-08T00:00:00.000Z",
  "modified": "2026-10-15T09:30:00.000Z",
  "pattern": "[domain-name:value = 'bad-logistics.example']",
  "pattern_type": "stix",
  "valid_from": "2026-10-08T00:00:00.000Z",
  "revoked": true
}
```

`created` tetap, `modified` maju, dan `revoked: true`. Konsumen yang hanya menyimpan nilai domain tanpa `id` tidak bisa memproses revoke ini dan akan terus memakai indikator basi. Itulah alasan praktis kenapa integrasi feed sebaiknya menyimpan `id` STIX, bukan hanya nilainya.

### 4.4 Alur TAXII polling inkremental

```
Konsep pertukaran (ilustrasi):
  1. GET https://taxii.mitra.example/taxii2/
       -> daftar api_roots, misal https://taxii.mitra.example/feeds/
  2. GET https://taxii.mitra.example/feeds/collections/
       -> collection "ransomware-logistik" (id 91a7..., can_read=true, can_write=false)
  3. GET .../collections/91a7.../objects/?added_after=2026-10-08T00:00:00Z&match[type]=indicator,relationship,malware
       Accept: application/taxii+json;version=2.1
       -> envelope: { "more": true, "next": "abc123", "objects": [ ... ] }
  4. Ulangi dengan next=abc123 sampai "more": false
  5. Simpan waktu pengambilan terakhir dari header X-TAXII-Date-Added-Last
       sebagai added_after untuk polling berikutnya
Catatan: patuhi auth, ToS, dan TLP; jangan tarik atau unggah data di luar izin.
```

Cara membaca: langkah 3 dan 5 adalah inti polling yang efisien. Tanpa `added_after`, klien menarik ulang seluruh isi collection setiap kali dan membebani kedua pihak. Bila jumlah objek tiba-tiba melonjak, cek dulu apakah penanda waktu pengambilan terakhir hilang, sebelum menyimpulkan ada kampanye besar.

### 4.5 Memetakan laporan ke objek STIX

Paragraf laporan fiktif: "Kampanye LOGI-FICTA, yang kami kaitkan dengan intrusion set ISET-FICTA, mengirim email berlampiran ke perusahaan logistik. Lampiran menjalankan ransomware-lab yang berkomunikasi ke bad-logistics.example."

```
Objek yang lahir dari paragraf itu:
  campaign       LOGI-FICTA
  intrusion-set  ISET-FICTA
  identity       "sektor logistik" (identity_class: class)
  attack-pattern Phishing: Spearphishing Attachment (external_references -> ATT&CK T1566.001)
  malware        ransomware-lab
  indicator      [domain-name:value = 'bad-logistics.example']
Relationship:
  campaign  attributed-to  intrusion-set
  campaign  targets        identity
  intrusion-set uses       attack-pattern
  intrusion-set uses       malware
  indicator indicates      malware
```

Lima kalimat menghasilkan enam objek dan lima relationship. Bandingkan dengan daftar IOC datar yang hanya berisi satu domain: konsumen kehilangan informasi sektor sasaran, teknik akses awal, dan kaitan ke intrusion set.

## 5. Lab praktik

**Prasyarat:** editor teks dan validator JSON (bisa ekstensi editor). Opsional: library pemvalidasi STIX di VM lab. Semua data fiktif, IOC di-defang di teks, tidak ada unggahan ke layanan publik.

1. **Siklus IOC.** Gambar siklus hidup IOC dan tulis kebijakan umur per jenis IOC untuk organisasi fiktifmu, lengkap dengan alasannya. Tulis juga apa yang terjadi setelah setahun bila expiry diabaikan.
2. **IOC kaya.** Ambil tiga IOC mentah fiktif (satu IP, satu domain, satu hash) dan ubah menjadi paket kaya konteks seperti bagian 4.1, termasuk tindakan yang direkomendasikan (blokir, alert, atau pengayaan saja) dan alasannya.
3. **Pengayaan sah.** Tulis daftar langkah pengayaan untuk satu domain, lalu tandai mana yang pasif, mana yang aktif (bisa terlihat oleh penyerang), dan mana yang melanggar (mengunggah lampiran insiden ke sandbox publik).
4. **Validasi IOC.** Tentukan mana yang ditolak dan kenapa: `8.8.8[.]8`, `10.20.30[.]40`, `cdn-fiktif[.]example` (CDN besar), `update-check[.]example` (didaftarkan 3 hari lalu), hash installer resmi aplikasi kantor.
5. **Bundle STIX.** Tulis bundle untuk paragraf di bagian 4.5 dengan seluruh objek dan relationship-nya. Validasi JSON-nya, lalu cek bahwa setiap `source_ref` dan `target_ref` menunjuk `id` yang ada.
6. **Pola.** Tulis tiga pola STIX: satu IP dalam subnet, satu hash SHA-256, dan satu gabungan nama file dan ukuran. Untuk masing-masing, tulis satu contoh nilai yang cocok dan satu yang tidak.
7. **Revoke.** Tulis versi revoke dari salah satu Indicator-mu dan jelaskan apa yang harus dilakukan SIEM konsumen saat menerimanya.
8. **TAXII.** Tulis urutan request untuk polling inkremental collection fiktif, termasuk cara menyimpan penanda waktu.

**Hasil yang sebaiknya tersimpan:**

- Kebijakan umur IOC per jenis beserta alasannya.
- Tiga paket IOC kaya konteks dengan tindakan yang direkomendasikan.
- Daftar langkah pengayaan yang dibedakan menjadi pasif, aktif, dan melanggar.
- Hasil validasi daftar IOC beserta alasan penolakan.
- Bundle STIX valid untuk paragraf laporan, beserta catatan pengecekan referensi.
- Tiga pola STIX dengan contoh positif dan negatif.
- Contoh Indicator yang di-revoke dan tindakan konsumen.
- Urutan request TAXII polling inkremental.

**Variasi tantangan:** ambil satu laporan kampanye publik yang kamu baca, modelkan sebagai bundle STIX lengkap (threat-actor atau intrusion-set, campaign, malware, attack-pattern, indicator, identity, dan relationship), lalu tulis satu paragraf tentang informasi apa yang hilang bila laporan yang sama hanya dibagikan sebagai daftar IOC CSV.

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Daftar IOC penuh noise | Expiry diabaikan | Terapkan `valid_until` dan peninjauan; pensiunkan yang basi |
| IOC tak bisa ditindak | Tanpa konteks | Perkaya: sumber, kaitan, keyakinan, sighting |
| False positive tinggi | IP bersama, CDN, atau resolver publik diblokir | Validasi sebelum operasionalisasi; pakai daftar pengecualian |
| Indicator yang sudah dicabut tetap memicu alert | Integrasi hanya menyimpan nilai, bukan `id` STIX | Simpan `id` dan proses `revoked` serta versi `modified` |
| Relationship tampil tanpa target | `source_ref` atau `target_ref` tidak cocok | Cocokkan `id` persis, termasuk prefiks tipe |
| Polling TAXII menarik ulang semua data | `added_after` tidak disimpan | Simpan penanda waktu dari header respons |
| IOC tidak pernah cocok di SIEM | Nilai masih ter-defang saat ingestion | Refang sebelum dimuat ke daftar pencocokan |
| Pengayaan bocorkan data | Unggah file ke sandbox publik | Cari berdasarkan hash; pakai sandbox internal |

## 7. Kesalahan umum dan jebakan

- **IOC tanpa konteks.** Nilai telanjang memaksa konsumen menebak; sertakan sumber, kaitan, keyakinan, dan tanggal.
- **Tidak memensiunkan IOC.** Indikator basi menjadi noise dan false positive; kelola expiry.
- **Memperlakukan semua sebagai IOC datar.** Bedakan observable, Indicator, dan TTP (Attack Pattern).
- **Pengayaan aktif yang membocorkan investigasi.** Membuka URL penyerang dari jaringan kantor atau mengunggah sampel memberi sinyal ke penyerang.
- **Mengira STIX sama dengan TAXII.** STIX adalah bahasa, TAXII adalah transport.
- **Menyamakan `confidence` STIX dengan skala internal.** Tulis pemetaan eksplisit, misalnya rendah 15-35, sedang 50-70, tinggi 85-100.
- **Menulis pola dengan nilai ter-defang.** Pola tidak akan pernah cocok.
- `[komunitas]` Umur IOC per jenis pada tabel bagian 3.3 adalah titik awal yang lazim di kalangan praktisi, bukan angka dari standar. Sesuaikan dengan data hit dan false positive di lingkunganmu.

## 8. Catatan terkini

- STIX 2.1 dan TAXII 2.1 tetap versi OASIS Standard terbaru sejak 10 Juni 2021 [S1][S2][S3]. Belum ada penerus yang berstatus standar; cek halaman OASIS CTI bila ingin memastikan.
- Channel di TAXII 2.1 masih berstatus dicadangkan, sehingga semua pertukaran berbasis polling.
- TLP 2.0 di STIX 2.1 memakai marking definition tambahan karena spesifikasi STIX 2.1 terbit dengan id marking TLP 1.0. Banyak platform sudah mendukung keduanya; periksa yang dipakai platform-mu.
- STIX 1.x dan TAXII 1.x (berbasis XML) sudah usang; feed yang masih hanya menawarkan versi itu patut dicurigai tidak dirawat.

## 9. Cheat sheet

```
IOC JENIS   hash < IP < URL < domain < artefak host/jaringan (sejajar Pyramid of Pain) ; TTP bukan IOC atomik
ISTILAH     observable (SCO, fakta) | Indicator (SDO, pola+klaim+validitas) | TTP (Attack Pattern)
SIKLUS      observasi -> validasi -> pengayaan -> operasionalisasi -> tinjauan -> pensiun (expiry wajib)
UMUR AWAL   IP 7-30 hari | URL 30 hari | domain 90 hari (tinjau) | hash 6-12 bulan  (kebijakan sendiri)
ENRICH      passive DNS, WHOIS/RDAP, ASN/geo, sertifikat TLS, reputasi, kaitan, SIGHTING INTERNAL
AMAN        sumber pasif dulu ; cari hash, jangan unggah file ; defang teks, refang sebelum ingestion
STIX 2.1    JSON ; 18 SDO ; SCO = nilai mentah ; SRO = relationship + sighting ; marking-definition = TLP
INDICATOR   wajib: type spec_version id created modified pattern pattern_type valid_from ; isi valid_until
POLA        [domain-name:value = 'x'] ; [ipv4-addr:value ISSUBSET 'a.b.c.0/24'] ; [file:hashes.'SHA-256' = 'h']
            gabung AND/OR/FOLLOWEDBY ; qualifier WITHIN n SECONDS ; pattern_type bisa sigma/yara/snort
VERSI       id sama + modified baru = versi baru ; revoked:true = cabut ; simpan id, bukan hanya nilai
TAXII 2.1   /taxii2/ -> api-root -> collections -> objects ; manifest ; status ; versions
FILTER      added_after (inkremental) ; match[type|id|version|spec_version] ; limit + next (paging)
            Channel hanya dicadangkan di 2.1 -> semua polling
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | OASIS STIX Version 2.1 (OASIS Standard, 10 Juni 2021) | https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html | primer | diakses 2026-10-10 | Tinggi. Daftar SDO, SCO, SRO, properti wajib Indicator, patterning, versi dan revoke |
| S2 | OASIS TAXII Version 2.1 (OASIS Standard, 10 Juni 2021) | https://docs.oasis-open.org/cti/taxii/v2.1/taxii-v2.1.html | primer | diakses 2026-10-10 | Tinggi. Endpoint, media type, filter, status Channel yang dicadangkan |
| S3 | OASIS: STIX Version 2.1 (halaman status standar) | https://www.oasis-open.org/standard/stix-version-2-1/ | primer | diakses 2026-10-09 | Tinggi. Status standar |
| S4 | David Bianco: The Pyramid of Pain | https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html | primer | diakses 2026-10-09 | Tinggi. Daya tahan jenis indikator |
| S5 | CTI-note Day 03-05 (tradecraft, framework, sumber) | (lokal) | rujukan internal | 2026-10-09 | Admiralty, Pyramid of Pain, etika pengumpulan |

**Catatan sumber:** umur IOC per jenis di bagian 3.3 dan pemetaan `confidence` ke skala internal di bagian 7 adalah praktik umum, bukan ketentuan standar; sesuaikan dengan data lingkunganmu. Id marking definition untuk TLP 2.0 di STIX tidak ditulis di sini karena berbeda dari id TLP 1.0 di spesifikasi STIX 2.1; cocokkan dengan dokumentasi platform yang kamu pakai. Nama header `X-TAXII-Date-Added-Last` mengikuti spesifikasi TAXII 2.1, tetapi tidak semua server mengirimkannya, jadi siapkan cadangan berupa timestamp objek terbaru yang diterima.
