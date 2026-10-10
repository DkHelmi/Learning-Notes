# Endpoint-Forensics-note: Windows Endpoint dan Memory Forensics

> Personal study notes. Not affiliated with or endorsed by any vendor or standards body mentioned. Not legal or audit advice.
>
> License: [CC BY 4.0](LICENSE).

## Tujuan

Kredibel di interview DFIR dan di kasus nyata: artefak endpoint, triage, dan memori dasar. Di luar cakupan: mobile, physical disk mendalam, prosedur court-ready.

Aturan bahasa, format, dan penanda mengikuti standar penulisan pribadi (STANDAR-NOTE.md), yang tidak disertakan di repo ini.

## Versi acuan dan temuan awal

Persiapan awal: 2026-10-07.

Tidak ada pengecekan versi tambahan saat persiapan awal. Versi KAPE, EZ Tools, Velociraptor, Volatility 3 dicek saat Day terkait ditulis.

Versi acuan yang dipakai di Day-Day yang sudah ditulis: Windows 10/11, EZ Tools .NET 9, Velociraptor 0.77.3, Volatility 3 2.28.2 (17 September 2026, sebagian plugin di subpaket `windows.malware.*`), Plaso 20260720. Versi per Day tercantum di front matter `versions_checked`.

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
| 01 | [Alur kerja DFIR swasta: triage vs full image, OOV, hashing, CoC](01-alur-kerja-dfir-swasta.md) |
| 02 | [Setup lab DFIR](02-setup-lab.md) |
| 03 | [Triage dengan KAPE](03-triage-kape.md) |
| 04 | [Velociraptor dasar untuk forensik](04-velociraptor-dasar.md) |
| 05 | [Windows event log untuk forensik](05-windows-event-log-forensik.md) |
| 06 | [Review Minggu 1](06-review-minggu-1.md) |
| 07 | [Artefak eksekusi](07-artefak-eksekusi.md) |
| 08 | [File system: MFT, USN, $LogFile, Recycle Bin](08-file-system-mft-usn.md) |
| 09 | [Registry forensics](09-registry-forensics.md) |
| 10 | [Aktivitas pengguna](10-aktivitas-pengguna.md) |
| 11 | [Persistence dan lateral movement](11-persistence-lateral-movement.md) |
| 12 | [Review Minggu 2](12-review-minggu-2.md) |
| 13 | [Super-timeline](13-super-timeline.md) |
| 14 | [Akuisisi memori dan Volatility 3 dasar](14-memori-volatility-dasar.md) |
| 15 | [Analisis proses di memori](15-analisis-proses-memori.md) |
| 16 | [Jaringan dan persistence di memori](16-jaringan-persistence-memori.md) |
| 17 | [Simulasi kasus 1](17-simulasi-kasus-1.md) |
| 18 | [Simulasi kasus 2](18-simulasi-kasus-2.md) |
| 19 | [Pelaporan forensik](19-pelaporan-forensik.md) |
| 20 | [Review akhir](20-review-akhir.md) |
| 21 | [Anti-forensics: pembersihan log, penghapusan jejak, dan deteksinya](21-anti-forensics.md) |
| 22 | [Disk dan volume terenkripsi: BitLocker, VeraCrypt, akuisisi](22-disk-volume-terenkripsi.md) |
| 23 | [Triage Linux dan macOS](23-triage-linux-macos.md) |
| 24 | [Browser dan artefak cloud sync: OneDrive dan Teams](24-browser-dan-cloud-sync.md) |
| 25 | [ETW dan Sysmon sebagai sumber forensik](25-etw-sysmon-forensik.md) |
| 26 | [Korelasi multi-host dan timeline kolaboratif](26-korelasi-multi-host.md) |

## Catatan repo

Jangan commit: data/log/screenshot dari pekerjaan, kredensial, token API, sampel berbahaya, PDF standar, atau materi berbayar pihak lain.

