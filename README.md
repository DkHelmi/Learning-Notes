# Catatan Belajar Security Analyst

> Personal study notes. Not affiliated with or endorsed by any vendor or standards body mentioned. Not legal or audit advice.
>
> License: [CC BY 4.0](LICENSE).

Kumpulan catatan belajar mandiri untuk membangun kemampuan sebagai security analyst profesional: SIEM, detection engineering, threat hunting, forensik endpoint dan jaringan, threat intelligence, malware triage, dan tata kelola keamanan. Isinya mengikuti apa yang dibutuhkan di pekerjaan nyata, bukan silabus satu ujian tertentu.

Setiap topik dipecah menjadi beberapa Day. Satu Day adalah satu unit bacaan: konsep, contoh, lab, lalu rangkuman. Urutan bacaan bebas, tetapi Day yang lebih awal sering dirujuk oleh Day berikutnya.

Aturan bahasa, format, dan akurasi untuk semua topik mengikuti standar penulisan pribadi (STANDAR-NOTE.md), yang tidak disertakan di repo ini.

## Topik dan urutan prioritas

| Urutan | Topik | Jumlah Day |
|---|---|---|
| 1 | [Splunk-Notes](Splunk-Notes/) | 29 |
| 2 | [Wazuh-note](Wazuh-note/) | 18 |
| 3 | [Detection-Engineering-note](Detection-Engineering-note/) | 17 |
| 4 | [Threat-Hunting-note](Threat-Hunting-note/) | 16 |
| 5 | [Endpoint-Forensics-note](Endpoint-Forensics-note/) | 20 |
| 6 | [Network-Forensics-note](Network-Forensics-note/) | 14 |
| 7 | [CTI-note](CTI-note/) | 12 |
| 8 | [Malware-Triage-note](Malware-Triage-note/) | 14 |
| 9 | [ISO27001-note](ISO27001-note/) | 14 |

Alasan urutan:

1. **Splunk** dulu karena SIEM adalah keterampilan yang paling banyak dicari untuk peran SOC dan dipakai setiap hari.
2. **Wazuh** berikutnya karena menjadi SIEM/XDR di lab pribadi; Day-Day berikutnya di topik lain banyak memakai Wazuh sebagai sumber data dan tempat menguji rule.
3. **Detection Engineering** membangun di atas Splunk dan Wazuh: menulis, menguji, dan merawat deteksi sebagai kode.
4. **Threat Hunting** memakai deteksi dan data yang sama, lalu mengubah temuan menjadi deteksi baru.
5. **Endpoint Forensics** dan 6. **Network Forensics** memperdalam investigasi setelah alert atau hunt menemukan sesuatu, sekaligus memanfaatkan pengalaman forensik dan ISP yang sudah ada.
7. **CTI** memberi prioritas untuk deteksi dan hunting; lebih bermakna setelah fondasi teknis di atas kuat.
8. **Malware Triage** butuh lab terisolasi dan dasar forensik endpoint.
9. **ISO 27001** paling akhir karena sifatnya tata kelola; nilainya paling terasa ketika kamu sudah bisa memetakan pekerjaan SOC/DFIR yang nyata ke klausul dan kontrol.

Urutan ini boleh diubah bila kebutuhan pekerjaan berubah.

## Struktur tiap folder

| File | Isi |
|---|---|
| `README.md` | Tujuan topik, versi acuan, temuan penting, dan daftar isi |
| `SOURCES.md` | Indeks sumber |
| `NN-<slug>.md` | Satu Day (nomor dua digit, lalu slug topik) |
| `LICENSE` | Lisensi CC BY 4.0 |

## Jangan di-commit

Data, log, atau screenshot dari pekerjaan; kredensial dan token; sampel malware; PDF standar atau materi berbayar milik pihak lain.
