---
day: 08
title: 'Platform CTI: MISP dan OpenCTI, model data, dan cara mengelola intelijen terstruktur'
researched_on: 2026-10-10
versions_checked: 'MISP 2.5.x; OpenCTI v7 (track LTS); STIX/TAXII 2.1; rujukan Day 02, 03, 07, 10, 11'
---

# Day 08: MISP dan OpenCTI ringan

Cakupan: peran Threat Intelligence Platform dalam siklus intelijen, model data MISP dan OpenCTI beserta field dan fitur yang dipakai sehari-hari, dan cara memilih serta menjaga kualitas data sebelum diekspor ke deteksi.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- menjelaskan peran Threat Intelligence Platform (TIP) dalam siklus intelijen dan batasnya.
- membaca event MISP: field event, attribute, `to_ids`, object, tag, galaxy, dan level distribusi.
- menjelaskan fitur MISP yang menjaga kualitas data: warninglist, sighting, dan decaying model.
- menjelaskan model graf OpenCTI: entity, observable, indicator, container, connector, dan marking.
- memilih platform sesuai kebutuhan dan merancang alur ingestion sampai ekspor dengan titik validasi yang jelas.

## 2. Konteks singkat

Begitu intelijen melampaui segelintir IOC, spreadsheet tidak lagi cukup. Kamu butuh ingestion feed otomatis, deduplikasi, korelasi, penyimpanan yang menjaga konteks dan relationship, kontrol berbagi, dan ekspor ke alat deteksi. Itulah fungsi TIP. Dua TIP open-source yang paling umum adalah MISP dan OpenCTI. Keduanya mendukung STIX dan TAXII (Day 07) dan mengotomasi tahap collection dan processing siklus intelijen (Day 02).

Day ini bersifat pengenalan: memahami model data dan alur kerja sampai bisa membaca isi platform dan merancang penggunaannya, bukan administrasi server. Pengetahuan ini dibutuhkan bahkan bila kamu tidak pernah mengelola instance sendiri, karena sebagai analis kamu akan mengisi, membaca, dan menilai data di dalamnya.

**Kapan dipakai:** mengelola volume intelijen, korelasi lintas sumber, berbagi dengan komunitas dan mitra, umpan ke deteksi.

**Kapan terbatas:** platform butuh pemeliharaan dan kurasi. Tanpa PIR dan tradecraft, TIP hanya menjadi gudang data yang terus membengkak.

## 3. Konsep inti

### 3.1 Apa itu TIP

TIP menyimpan, mengorelasikan, dan membagikan intelijen secara terstruktur. Fungsi intinya:

| Fungsi | Isi | Tahap siklus (Day 02) |
|---|---|---|
| Ingestion | Menarik feed, laporan, dan input manual lewat STIX/TAXII, format MISP, CSV, atau API | Collection |
| Normalisasi dan deduplikasi | Menyamakan format, menggabungkan indikator yang sama dari banyak sumber | Processing |
| Korelasi | Menautkan event atau entity yang berbagi nilai | Processing, awal analysis |
| Pengayaan | Menambah konteks otomatis (reputasi, ATT&CK, passive DNS) lewat modul | Processing |
| Penyimpanan terstruktur | Menjaga konteks, relationship, dan riwayat | Semua tahap |
| Sharing | Berbagi ke komunitas atau mitra dengan kontrol TLP dan distribusi | Dissemination |
| Ekspor | Mengirim indikator ke SIEM, firewall, IDS, EDR | Dissemination, operasionalisasi |

Yang tidak bisa dilakukan TIP: menetapkan arah (PIR) dan melakukan analisis. Platform bisa memberi tahu bahwa satu domain muncul di tiga feed; ia tidak bisa memberi tahu apakah domain itu relevan bagi organisasimu.

### 3.2 MISP: event dan attribute

MISP (Malware Information Sharing Platform) berpusat pada event [S1]. Satu event adalah wadah untuk satu insiden, satu laporan, atau satu kumpulan indikator yang saling terkait.

Field event yang paling sering kamu baca:

| Field | Arti | Nilai |
|---|---|---|
| `info` | Judul singkat event | Teks bebas |
| `date` | Tanggal kejadian atau laporan | Tanggal |
| `threat_level_id` | Tingkat ancaman menurut pembuat | 1 High, 2 Medium, 3 Low, 4 Undefined |
| `analysis` | Status analisis | 0 Initial, 1 Ongoing, 2 Completed |
| `distribution` | Siapa yang boleh menerima event | 0-4 (bagian 3.4) |
| `published` | Apakah event sudah diterbitkan | true/false |
| `Orgc` | Organisasi pembuat asli | Nama organisasi |

Publish adalah titik penting. Event yang belum di-publish masih draf; ketika di-publish, MISP menyinkronkannya ke instance lain sesuai distribusi dan memicu ekspor. Biasakan memeriksa isi dengan teliti sebelum publish, karena menarik kembali data yang sudah tersinkron ke banyak instance jauh lebih sulit.

Di dalam event ada attribute, yaitu satu nilai dengan tipe dan kategori:

| Field attribute | Arti |
|---|---|
| `type` | Jenis nilai: `ip-dst`, `ip-src`, `domain`, `hostname`, `url`, `sha256`, `md5`, `email-src`, `filename`, dan banyak lagi |
| `category` | Konteks: `Network activity`, `Payload delivery`, `Artifacts dropped`, `Persistence mechanism`, `External analysis` |
| `value` | Nilainya (disimpan tanpa defang) |
| `to_ids` | Flag apakah nilai ini layak dipakai untuk deteksi otomatis |
| `comment` | Catatan analis |
| `first_seen`, `last_seen` | Rentang waktu terlihat |

Flag `to_ids` adalah salah satu field paling penting di MISP. Hanya attribute dengan `to_ids` aktif yang ikut ekspor ke format deteksi secara default. Attribute konteks, misalnya IP resolver publik yang disebut di laporan atau nama file umum, sebaiknya disimpan dengan `to_ids` mati: informasinya tetap ada untuk analis, tetapi tidak menjadi alert.

**Object** mengelompokkan beberapa attribute yang saling melengkapi berdasarkan template, misalnya object `file` (nama, ukuran, beberapa hash), `domain-ip` (domain dan IP resolusinya), `email` (pengirim, subjek, lampiran), atau `url`. Object menjaga bahwa hash dan nama file itu milik file yang sama, bukan dua fakta lepas.

### 3.3 Tag, taxonomy, dan galaxy

MISP membedakan dua mekanisme label [S1]:

- **Taxonomy** adalah kosakata tag yang terkontrol, ditulis dalam bentuk `namespace:predikat="nilai"`. Contoh yang sering dipakai: `tlp:amber`, `tlp:amber+strict`, `admiralty-scale:source-reliability="b"`, `admiralty-scale:information-credibility="2"`, `PAP:AMBER` (Permissible Actions Protocol, batas tindakan yang boleh dilakukan penerima terhadap indikator), dan `workflow:state="draft"`.
- **Galaxy** adalah basis pengetahuan berisi cluster dengan deskripsi dan sinonim: aktor ancaman, keluarga malware, teknik ATT&CK, sektor. Menempelkan cluster galaxy ATT&CK ke event memberi pemetaan teknik yang bisa dicari lintas event.

Taxonomy menjawab "bagaimana menangani informasi ini" (TLP, PAP, keandalan), galaxy menjawab "ini tentang apa" (aktor, teknik, malware).

### 3.4 Distribusi, sync, dan sharing group

Setiap event dan attribute punya level distribusi:

| Nilai | Nama | Siapa menerima |
|---|---|---|
| 0 | Your organisation only | Hanya organisasimu di instance ini |
| 1 | This community only | Semua organisasi di instance ini |
| 2 | Connected communities | Instance ini dan instance yang tersambung satu lompatan |
| 3 | All communities | Menyebar ke seluruh jaringan sync tanpa batas lompatan |
| 4 | Sharing group | Daftar organisasi dan instance yang didefinisikan eksplisit |

Attribute punya opsi tambahan `Inherit event`, yang mengikuti distribusi event-nya.

Distribusi dan TLP adalah dua hal berbeda. Distribusi adalah kontrol teknis: ke mana data disinkronkan. TLP adalah kesepakatan manusia: apa yang boleh dilakukan penerima dengan informasi itu (Day 11). Keduanya harus konsisten. Event bertag `tlp:red` dengan distribusi "All communities" adalah kesalahan konfigurasi yang serius.

### 3.5 Fitur kualitas data MISP

Tiga fitur yang membedakan MISP yang terawat dari tumpukan feed:

- **Warninglist:** daftar nilai yang dikenal sah atau tidak spesifik, misalnya domain populer, rentang IP CDN dan cloud besar, resolver DNS publik, dan alamat privat RFC 1918. Attribute yang cocok dengan warninglist diberi peringatan, dan ekspor bisa dikonfigurasi untuk mengecualikannya. Ini pertahanan pertama terhadap false positive massal.
- **Sighting:** catatan bahwa sebuah attribute benar-benar terlihat (atau terbukti false positive) di lingkungan seseorang, dengan waktu. Sighting memberi bukti bahwa indikator masih hidup. Sighting bertipe false positive memberi sinyal kuat untuk menonaktifkan `to_ids`.
- **Decaying model:** model skor yang menurunkan nilai attribute seiring waktu sejak terakhir terlihat. Skor awal bisa diturunkan dari tag (misalnya keandalan Admiralty), lalu menurun dengan kecepatan yang ditentukan per tipe; sighting baru menaikkan kembali. Indikator dengan skor di bawah ambang tidak ikut ekspor. Ini implementasi expiry (Day 07) yang otomatis.

### 3.6 Feed, ekspor, dan API MISP

MISP bisa mengonsumsi feed dalam format MISP (event lengkap dengan konteks), CSV, atau freetext. Feed format MISP paling kaya karena membawa tag dan object; feed CSV atau freetext hanya membawa nilai dan perlu diberi konteks sendiri.

Untuk ekspor, MISP menyediakan API `restSearch` pada endpoint `/events/restSearch` dan `/attributes/restSearch`. Parameter yang sering dipakai: `returnFormat` (misalnya `json`, `csv`, `text`, `stix2`, `suricata`, `snort`), `type`, `tags`, `to_ids`, `last` (rentang waktu relatif, misalnya `7d`), `published`, dan `enforceWarninglist`. Contohnya ada di bagian 4.2.

### 3.7 OpenCTI: graf pengetahuan berbasis STIX

OpenCTI (dikembangkan Filigran) memakai STIX 2.1 sebagai model data dasarnya [S2]. Semua data menjadi node dan edge dalam graf pengetahuan.

| Konsep | Isi |
|---|---|
| Entity | Objek STIX domain: Threat Actor, Intrusion Set, Campaign, Malware, Tool, Attack Pattern, Vulnerability, Identity (sektor, organisasi), Location |
| Observable | Nilai teknis (SCO): IP, domain, URL, file, email |
| Indicator | Pola deteksi dengan skor dan masa berlaku; bisa dibuat dari observable dan sebaliknya |
| Relationship | Edge STIX: `uses`, `targets`, `indicates`, `attributed-to`, `based-on` |
| Container | Wadah yang mengelompokkan objek: Report, Grouping, Note, Opinion, dan Case (misalnya Case untuk incident response atau request for information) |
| Marking | TLP dan PAP; dipakai juga untuk kontrol akses pengguna |
| Connector | Modul integrasi |

Connector dibagi menurut fungsi: external import (menarik data dari luar, misalnya dataset ATT&CK, feed TAXII, atau instance MISP), internal enrichment (memperkaya observable yang ada, misalnya lewat layanan reputasi), internal import file (mengekstrak isi PDF atau STIX yang diunggah), internal export file (menghasilkan berkas ekspor), dan stream (mengalirkan perubahan ke sistem lain, termasuk SIEM).

Pembedaan observable dan indicator di OpenCTI mengikuti Day 07. Observable adalah fakta; indicator adalah klaim deteksi. Indicator di OpenCTI punya skor 0-100, `valid_from` dan `valid_until`, serta flag deteksi yang menandai apakah indicator layak dikirim ke alat deteksi. Platform juga mendukung aturan penurunan skor indicator seiring waktu, mirip decaying model MISP. Nama menu dan opsi persisnya berubah antar versi, jadi cek di instance-mu.

Untuk ekspor, OpenCTI menyediakan live stream, collection TAXII, dan feed CSV yang bisa diisi dengan filter (misalnya hanya indicator dengan skor minimal tertentu dan flag deteksi aktif).

Komponen di balik OpenCTI (API GraphQL, worker, message queue, penyimpanan objek, dan mesin pencarian berbasis Elasticsearch atau OpenSearch) membuatnya lebih berat dijalankan daripada MISP. Itu perlu diperhitungkan untuk lab pribadi.

### 3.8 MISP vs OpenCTI

| Aspek | MISP | OpenCTI |
|---|---|---|
| Pusat model | Event berisi attribute dan object | Graf entity dan relationship STIX |
| Kekuatan | Berbagi indikator antar komunitas, korelasi nilai, warninglist | Memodelkan aktor, kampanye, dan perilaku; navigasi graf |
| Kontrol kualitas | `to_ids`, warninglist, sighting, decaying model | Skor indicator, flag deteksi, aturan penurunan skor |
| Berbagi | Sync antar instance, distribusi 0-4, sharing group | TAXII, stream, marking-based access |
| Beban operasional | Lebih ringan | Lebih berat (banyak komponen) |
| Cocok untuk | Pertukaran IOC dengan ISAC atau CERT, korelasi cepat | Analisis aktor dan kampanye berlapis, pelaporan ke manajemen |

Keduanya tidak saling eksklusif. Pola yang sering ditemui: MISP sebagai pintu pertukaran dengan komunitas, OpenCTI sebagai basis pengetahuan analis, dihubungkan lewat connector MISP di OpenCTI.

Cara memilih: mulai dari konsumen dan PIR. Bila kebutuhan utamamu menerima dan membagikan indikator dengan ISAC, MISP saja sering cukup. Bila kamu harus menjawab pertanyaan seperti "aktor mana yang menargetkan sektor kita dan teknik apa yang belum kita deteksi", model graf OpenCTI lebih membantu.

### 3.9 Korelasi yang menyesatkan

Korelasi otomatis adalah kekuatan sekaligus jebakan. Dua event yang sama-sama memuat IP resolver publik, domain CDN, atau hash file sistem yang sah akan tertaut walaupun tidak berhubungan. Analis yang tidak teliti lalu menyimpulkan dua kampanye berasal dari aktor yang sama. Pertahanannya: warninglist aktif, `to_ids` dimatikan untuk nilai konteks, korelasi dimatikan untuk attribute generik, dan setiap tautan yang mau dipakai dalam penilaian diperiksa manual (Day 03, bias konfirmasi).

## 4. Contoh artefak intelijen

Semua contoh di bagian ini fiktif dan berupa keluaran ilustrasi. IOC di-defang di teks.

### 4.1 Event MISP (disederhanakan)

```
Event (fiktif)
  info            : Kampanye ransomware sektor logistik LOGI-FICTA (fiktif)
  date            : 2026-10-08
  threat_level_id : 2 (Medium)
  analysis        : 1 (Ongoing)
  distribution    : 4 (Sharing group: ISAC-Logistik-Fiktif)
  published       : false
  Tags            : tlp:amber ; PAP:GREEN ; admiralty-scale:source-reliability="b"
                    admiralty-scale:information-credibility="2" ; workflow:state="draft"
  Galaxy          : mitre-attack-pattern = Phishing: Spearphishing Attachment (T1566.001)
  Attributes:
    domain    Network activity  bad-logistics[.]example    to_ids=1
    ip-dst    Network activity  203.0.113[.]50             to_ids=1
    ip-dst    Network activity  8.8.8[.]8                  to_ids=0  (resolver yang dipakai sampel; konteks)
                                                            warninglist: public DNS resolvers
  Object file:
    filename  invoice-1008.js   to_ids=0
    sha256    <hash-fiktif>      to_ids=1
  Korelasi: bad-logistics[.]example juga ada di Event #1123 (mitra lain, 2026-10-05)
```

Cara membaca:

- Event masih draf (`published: false`, `workflow:state="draft"`), jadi belum tersinkron dan belum ikut ekspor.
- Distribusi sharing group sejalan dengan `tlp:amber`. Bila tag-nya `tlp:red`, distribusi harus diturunkan ke 0.
- `8.8.8[.]8` disimpan sebagai konteks dengan `to_ids=0` dan ditandai warninglist. Seandainya `to_ids=1`, ekspor ke firewall akan memblokir resolver publik.
- Nama file `to_ids=0` karena nama seperti itu mudah ditiru dan terlalu umum; hash-nya `to_ids=1`.
- Korelasi ke Event #1123 adalah petunjuk, bukan kesimpulan. Buka event itu dan nilai apakah tautannya bermakna.

### 4.2 Ekspor lewat restSearch

```
POST /attributes/restSearch
Authorization: <API key analis>
Accept: application/json
Content-Type: application/json

{
  "returnFormat": "csv",
  "type": ["domain", "ip-dst", "sha256"],
  "to_ids": 1,
  "tags": ["tlp:amber", "tlp:green", "tlp:clear"],
  "published": 1,
  "last": "30d",
  "enforceWarninglist": 1
}
```

Keluaran ilustrasi setelah event di bagian 4.1 divalidasi dan di-publish:

```
uuid,event_id,category,type,value,comment,to_ids,date
5f1e...,1201,Network activity,domain,bad-logistics.example,,1,1759881600
5f1f...,1201,Network activity,ip-dst,203.0.113.50,,1,1759881600
5f20...,1201,Payload delivery,sha256,<hash-fiktif>,,1,1759881600
```

Cara membaca: hanya tiga baris walaupun event memuat lima nilai. `8.8.8.8` hilang karena `to_ids=0` dan warninglist; nama file hilang karena tipenya tidak diminta dan `to_ids=0`. Sebelum event di-publish, filter `published: 1` membuat hasilnya kosong. Bila ekspor tiba-tiba menghasilkan puluhan ribu baris, cek apakah filter `last` dan `to_ids` terlewat.

Kapan gagal: tag TLP:RED tidak ada di filter, jadi aman; tetapi bila filter `tags` dihapus, data TLP:RED ikut terekspor ke sistem yang mungkin diakses pihak lain. Filter TLP di ekspor adalah kontrol, bukan hiasan.

### 4.3 Graf OpenCTI untuk kampanye yang sama

```
Report "LOGI-FICTA, laporan vendor fiktif 2026-10-07" (marking TLP:AMBER) berisi:
  [Intrusion Set: ISET-FICTA] --uses--> [Malware: ransomware-lab]
  [Intrusion Set: ISET-FICTA] --uses--> [Attack Pattern: T1566.001]
  [Campaign: LOGI-FICTA] --attributed-to--> [Intrusion Set: ISET-FICTA]
  [Campaign: LOGI-FICTA] --targets--> [Sector: Logistik] ; --targets--> [Country: Indonesia]
  [Indicator: bad-logistics.example, skor 60, valid_until 2027-01-08, deteksi=ya]
       --indicates--> [Malware: ransomware-lab]
  [Indicator] --based-on--> [Observable: Domain-Name bad-logistics.example]
Pivot: buka Attack Pattern T1566.001 -> lihat semua Intrusion Set lain yang memakainya
       dan menargetkan sektor Logistik.
```

Cara membaca: report adalah container, jadi kamu bisa melihat objek mana berasal dari laporan mana. Pivot dari attack pattern ke sektor adalah pertanyaan yang sulit dijawab di MISP tanpa pencarian manual lintas event.

### 4.4 Alur ingestion sampai ekspor dengan titik validasi

```
Feed TAXII mitra + feed MISP ISAC + laporan PDF
  -> ingestion (connector / feed)                       [otomatis]
  -> deduplikasi + korelasi + warninglist               [otomatis]
  -> pengayaan (passive DNS, reputasi, ATT&CK)          [otomatis]
  -> TITIK VALIDASI ANALIS                              [manual]
       relevan dengan PIR? sumber dan keandalan? TLP sumber?
       nilai generik? -> to_ids=0 / flag deteksi mati
       beri keyakinan + valid_until
  -> publish / set flag deteksi
  -> ekspor: CSV/TAXII/stream ke SIEM (filter: to_ids, skor, TLP, umur)
  -> sighting dan false positive dari SOC kembali ke TIP
```

Titik validasi analis adalah satu-satunya langkah manual, dan langkah itulah yang paling sering dilewati saat tim sibuk.

## 5. Lab praktik

**Prasyarat:** editor teks. Opsional: instance MISP atau OpenCTI di VM lab terpisah tanpa koneksi ke data kerja; ikuti panduan instalasi resmi masing-masing. Data fiktif, IOC di-defang di teks.

1. **Model MISP.** Modelkan kampanye fiktif sebagai satu event MISP lengkap: field event, minimal enam attribute dengan kategori dan `to_ids` yang dipertimbangkan, satu object `file`, tag TLP, PAP, Admiralty, dan satu galaxy ATT&CK.
2. **Keputusan `to_ids`.** Untuk setiap attribute, tulis satu kalimat alasan `to_ids` aktif atau mati.
3. **Distribusi.** Tetapkan distribusi untuk tiga versi event: TLP:CLEAR, TLP:AMBER, TLP:RED. Jelaskan kenapa.
4. **Warninglist.** Buat daftar lima nilai fiktif yang seharusnya tertangkap warninglist dan tuliskan kategorinya (resolver publik, CDN, alamat privat, domain populer, hash file sistem).
5. **Model OpenCTI.** Modelkan kampanye yang sama sebagai report berisi entity, observable, indicator, dan relationship.
6. **Pivot.** Tulis dua pertanyaan analis yang lebih mudah dijawab di graf OpenCTI dan satu yang lebih mudah dijawab di MISP.
7. **Ekspor.** Tulis request restSearch untuk mengekspor indikator layak deteksi 30 hari terakhir dengan TLP:AMBER ke bawah. Jelaskan setiap filter dan apa yang terjadi bila filter itu dihapus.
8. **Korelasi palsu.** Tulis skenario di mana dua event tidak berhubungan tertaut karena nilai generik, dan langkah yang mencegahnya.

**Hasil yang sebaiknya tersimpan:**

- Event MISP fiktif lengkap dengan alasan `to_ids` per attribute.
- Tabel distribusi untuk tiga label TLP.
- Daftar contoh warninglist.
- Model graf OpenCTI kampanye yang sama.
- Daftar pertanyaan pivot per platform.
- Request ekspor beranotasi.
- Skenario korelasi palsu dan pencegahannya.

**Variasi tantangan:** tulis rekomendasi satu halaman untuk organisasi fiktif dengan tim CTI dua orang yang sudah menjadi anggota ISAC: apakah perlu MISP, OpenCTI, atau keduanya. Sertakan beban pemeliharaan, kebutuhan konsumen, dan jalur ekspor ke SIEM.

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Blokir mengenai layanan sah | Nilai generik dengan `to_ids=1`, warninglist mati | Aktifkan warninglist dan `enforceWarninglist`; matikan `to_ids` untuk konteks |
| Korelasi menautkan event tak terkait | Nilai bersama (CDN, resolver) | Matikan korelasi untuk attribute generik; validasi manual |
| Data membengkak | Ingestion semua feed tanpa seleksi | Pilih feed berdasarkan PIR; terapkan decaying model atau skor |
| Ekspor deteksi berisik | Indikator basi atau belum divalidasi | Filter umur, skor, dan flag deteksi |
| Event tidak muncul di instance mitra | Belum di-publish atau distribusi terlalu sempit | Cek `published` dan level distribusi |
| Data TLP:RED muncul di mitra | Distribusi tidak konsisten dengan TLP | Samakan distribusi dengan TLP; audit sharing group |
| OpenCTI lambat atau tidak stabil | Sumber daya kurang untuk banyak komponen | Cek kebutuhan resmi; kurangi connector aktif di lab |

## 7. Kesalahan umum dan jebakan

- **Mengira platform menggantikan proses.** Tanpa PIR dan tradecraft, TIP hanya menumpuk data.
- **`to_ids` aktif untuk semua attribute.** Konteks berubah menjadi alert; false positive meledak.
- **Menyamakan distribusi dengan TLP.** Distribusi mengatur sync, TLP mengatur perilaku penerima. Keduanya harus konsisten.
- **Publish terlalu cepat.** Data yang sudah tersinkron sulit ditarik kembali.
- **Percaya korelasi otomatis.** Tautan adalah petunjuk; nilai generik menghasilkan tautan palsu.
- **Mengekspor tanpa filter TLP.** Ekspor ke sistem yang diakses vendor atau MSSP bisa melanggar TLP sumber.
- `[komunitas]` Pola MISP untuk pertukaran komunitas dan OpenCTI untuk basis pengetahuan analis, dihubungkan lewat connector, umum ditemui di praktik. Kecocokannya untuk tim kecil bergantung kapasitas pemeliharaan.

## 8. Catatan terkini

- MISP terus rilis cepat di seri 2.5; nomor versi patch berubah sering, jadi catat versi instance-mu saat mencatat perilaku fitur [S1].
- OpenCTI v7 memperkenalkan track LTS untuk stabilitas [S2][S4]. Penomoran versi dan masa dukungan LTS perlu dicek di catatan rilis resminya.
- Keduanya selaras dengan STIX/TAXII 2.1 (Day 07) dan punya ekosistem connector atau modul yang luas, termasuk impor dataset ATT&CK.
- Nama menu dan beberapa field berubah antar versi. Konsep di Day ini (to_ids, distribusi, warninglist, observable vs indicator) stabil; tampilan tidak.

## 9. Cheat sheet

```
TIP         ingest -> normalisasi/dedup -> korelasi -> enrich -> VALIDASI ANALIS -> share/ekspor ; bukan pengganti PIR/analisis
MISP EVENT  info | date | threat_level_id 1-4 | analysis 0-2 | distribution 0-4 | published | Orgc
ATTRIBUTE   type | category | value | to_ids (ikut ekspor deteksi?) | comment | first_seen/last_seen
OBJECT      kelompok attribute (file, domain-ip, email, url)
LABEL       taxonomy = cara menangani (tlp:, PAP:, admiralty-scale:, workflow:) ; galaxy = tentang apa (aktor, ATT&CK)
DISTRIBUSI  0 org | 1 komunitas instance | 2 connected | 3 all | 4 sharing group ; konsisten dengan TLP
KUALITAS    warninglist (nilai sah/generik) | sighting (bukti terlihat/FP) | decaying model (skor turun)
EKSPOR      /attributes/restSearch : returnFormat, type, to_ids, tags, published, last, enforceWarninglist
OPENCTI     entity | observable (fakta) | indicator (skor, valid_until, flag deteksi) | relationship | container | marking
CONNECTOR   external import | internal enrichment | import file | export file | stream
PILIH       tukar IOC komunitas -> MISP | analisis aktor/kampanye berlapis -> OpenCTI | sering keduanya
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | MISP Project: dokumentasi, MISP book, rilis | https://www.misp-project.org/ | primer | diakses 2026-10-09 | Tinggi. Model event/attribute, to_ids, distribusi, taxonomy, galaxy, warninglist, sighting, decaying model, restSearch |
| S2 | OpenCTI (Filigran): dokumentasi | https://docs.opencti.io/ | primer | diakses 2026-10-09 | Tinggi. Model graf STIX, observable vs indicator, container, connector, stream |
| S3 | OASIS STIX Version 2.1 | https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html | primer | diakses 2026-10-09 | Tinggi. Model data dasar OpenCTI |
| S4 | Filigran: OpenCTI v7 (track LTS) | https://filigran.io/opencti-v7/ | sekunder | diakses 2026-10-09 | Sedang-tinggi. Pengumuman rilis v7 |
| S5 | CTI-note Day 02, 03, 07, 11 | (lokal) | rujukan internal | 2026-10-09 | Siklus, Admiralty, STIX, TLP |

**Catatan sumber:** konsep model data MISP dan OpenCTI stabil, tetapi nama menu, opsi flag deteksi di OpenCTI, dan perilaku default ekspor bergantung versi; cocokkan dengan instance-mu. Nilai numerik `threat_level_id`, `analysis`, dan `distribution` mengikuti dokumentasi MISP dan jarang berubah. Rincian masa dukungan track LTS OpenCTI v7 berasal dari pengumuman vendor dan perlu dicocokkan dengan catatan rilis resmi.
