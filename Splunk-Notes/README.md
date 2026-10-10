# Splunk-Notes: Splunk Enterprise dan Enterprise Security untuk analyst

> Personal study notes. Not affiliated with or endorsed by any vendor or standards body mentioned. Not legal or audit advice.
>
> License: [CC BY 4.0](LICENSE).

## Tujuan

Mampu memakai Splunk Enterprise dan Enterprise Security sebagai analyst profesional: menulis SPL yang efisien, membaca dan membangun detection, menjalankan risk based alerting, menginvestigasi finding sampai selesai, dan memahami sisi platform yang menentukan apakah semua itu bisa dipercaya (onboarding data, retensi, kuota search, kontrol akses). Bagian yang paling banyak digali karena paling sering dipakai dan paling mudah salah: `tstats`, `foreach`, CIM dan data model beserta acceleration, Asset and Identity, RBA, alur kerja ES, dan SOAR playbook.

Aturan bahasa, format, dan penanda mengikuti standar penulisan pribadi (STANDAR-NOTE.md), yang tidak disertakan di repo ini.

## Peta 35 Day

| Kelompok | Day | Fokus |
|---|---|---|
| 1 | 01-07 | SPL dan search efisien, ditutup review |
| 2 | 08-14 | Sumber data, CIM, data model, Asset and Identity, organisasi SOC, framework |
| 3 | 15-23 | Ancaman, threat intel, TTP, investigasi, metrik, istilah dan dashboard ES, RBA, detection |
| 4 | 24-29 | Hunting, adaptive response, SOAR, dua Day review dan rencana memperkuat kelemahan |
| 5 | 30-35 | Sisi platform dan operasi: onboarding data, arsitektur dan biaya, penyimpanan hasil, Mission Control, kontrol akses, dan studi kasus investigasi |

## Versi acuan

Catatan disusun mulai 2026-10-07. Versi acuan: Splunk Enterprise 10.6, ES 8.7.0, CIM 6.4, SSE 3.8.x, ESCU v6.7.0, SOAR on-prem 8.6.0, MITRE ATT&CK v19.2.

## Temuan penting

- **Istilah ES 8 berbeda dari ES 7.** Correlation search menjadi detection, notable event menjadi finding, contributing events menjadi intermediate finding, Incident Review menjadi analyst queue, risk object menjadi entity, threat object menjadi observable. Untuk risk notable, glosarium ES 8.7 memetakannya ke finding, sedangkan dalam praktik outputnya adalah finding group dari finding-based detection. Dokumentasi dan tulisan lama memakai istilah ES 7, jadi dua-duanya perlu dikenali. Lihat Day 06, 20, dan 28.
- **MITRE ATT&CK v19 (April 2026).** Defense Evasion dipecah menjadi Stealth (TA0005) dan Defense Impairment (TA0112), sehingga kini ada 15 taktik. Daftar ini sesuai attack.mitre.org per v19.2. Materi lama masih menyebut 14 taktik. Lihat Day 08, 15, dan 17.
- **Lima tahap investigasi** berasal dari artikel Splunk Lantern: Review events, Assessment, Determine risk, Mitigate, Re-assess. Materi pelatihan resmi bisa memakai nama sedikit berbeda; konsepnya tetap sama.
- **Kategori hunting** (configuration, modeling, indicators, behavioral analytics) mengikuti model Dragos "Four Types of Threat Detection" dan matriks 2x2 Robert M. Lee (environment atau threat, known atau unknown), dengan contoh CRASHOVERRIDE di Day 24. Model ini milik Dragos, bukan kerangka resmi Splunk.
- Dokumentasi resmi kini di help.splunk.com; tautan docs.splunk.com lama masih beredar dan sebagian sudah dialihkan. Klaim yang hanya berasal dari forum komunitas ditandai `[komunitas]` di Day terkait dan perlu diuji di lab.

## Struktur folder

| File | Isi |
|---|---|
| `README.md` | Tujuan, versi acuan, temuan penting, dan daftar isi |
| `SOURCES.md` | Indeks sumber yang dipakai di semua Day |
| `NN-<slug>.md` | Satu Day per file |
| `LICENSE` | Lisensi CC BY 4.0 |

## Daftar isi

| Day | Topik |
|---|---|
| 01 | [tstats](01-tstats.md) |
| 02 | [transaction dan first/last](02-transaction-first-last.md) |
| 03 | [rex dan eval](03-rex-eval.md) |
| 04 | [foreach, lookup, makeresults](04-foreach-lookup-makeresults.md) |
| 05 | [Search efisien](05-search-efisien.md) |
| 06 | [Sumber daya SPL di ES, SSE, Lantern](06-sumber-daya-spl-es-sse-lantern.md) |
| 07 | [Review Minggu 1](07-review-minggu-1.md) |
| 08 | [Defenses dan sumber data](08-defenses-dan-sumber-data.md) |
| 09 | [SIEM practices, CIM, data model](09-siem-cim-data-model.md) |
| 10 | [Acceleration dan Asset and Identity](10-acceleration-asset-identity.md) |
| 11 | [Field CIM untuk investigasi](11-field-cim-investigasi.md) |
| 12 | [SSE dan ES menilai sumber data](12-sse-es-menilai-sumber-data.md) |
| 13 | [Organisasi SOC](13-organisasi-soc.md) |
| 14 | [Framework, CIA, risiko](14-framework-cia-risiko.md) |
| 15 | [Serangan dan istilah](15-serangan-dan-istilah.md) |
| 16 | [Tiers threat intel dan annotations](16-tiers-threat-intel-annotations.md) |
| 17 | [TTP](17-ttp.md) |
| 18 | [Continuous monitoring dan lima tahap investigasi](18-continuous-monitoring-5-tahap-investigasi.md) |
| 19 | [Metrik dan disposisi](19-metrik-dan-disposisi.md) |
| 20 | [Istilah ES](20-istilah-es.md) |
| 21 | [Dashboard ES](21-dashboard-es.md) |
| 22 | [Risk framework dan RBA](22-risk-framework-rba.md) |
| 23 | [Correlation search dan detection](23-correlation-search.md) |
| 24 | [Teknik hunting](24-teknik-hunting.md) |
| 25 | [Long tail, outlier, hypothesis hunting](25-long-tail-outlier-hypothesis.md) |
| 26 | [Adaptive response action](26-adaptive-response.md) |
| 27 | [SOAR playbook](27-soar-playbook.md) |
| 28 | [Review paruh pertama: SOC, ancaman, data, investigasi](28-review-domain-1-4.md) |
| 29 | [Review akhir SPL, hunting, dan respons](29-review-domain-5-6-weak-spot.md) |
| 30 | [Onboarding data dan konfigurasi index-time](30-onboarding-data-index-time.md) |
| 31 | [Arsitektur dan operasi: bucket, retensi, cluster, biaya ingest, scheduler](31-arsitektur-dan-operasi.md) |
| 32 | [Summary index, KV store lookup, dan metrics](32-summary-index-kvstore-metrics.md) |
| 33 | [Mission Control, investigation, response plan, dan threat intelligence ES 8](33-mission-control-investigasi-threat-intel.md) |
| 34 | [RBAC, srchFilter, dan penanganan data sensitif](34-rbac-dan-data-sensitif.md) |
| 35 | [Tiga studi kasus investigasi: phishing, serangan web, lateral movement](35-studi-kasus-investigasi.md) |

## Catatan repo

Jangan commit: data, log, atau screenshot dari pekerjaan; kredensial dan token API; sampel berbahaya; PDF standar atau materi berbayar milik pihak lain.
