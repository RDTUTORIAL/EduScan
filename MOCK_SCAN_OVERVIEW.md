# EduScan Mock Scan Backend – Tooling Breakdown

Ikhtisar ringkas cara `server/app/services/mock_scans.py` mensimulasikan tiap fitur. Semua tool yang dipakai (utama & fallback) dijelaskan beserta alasan dan fungsi utamanya.

## Port Scanner
- **Tool utama**: `nmap -sS -Pn -p <ports>` (jika terpasang). Dipakai karena:
  - SYN scan cepat, akurat untuk status open/closed/filtered.
  - Output grepable mudah diparse tanpa opsi tambahan.
- **Fallback**: Python `socket`/`ssl` banner grab per port jika `nmap` tidak ada atau error.
- **Apa yang dilakukan**: list port umum, jalankan nmap, hitung summary, nilai risiko dari kombinasi layanan, sertakan perintah yang dijalankan (nmap atau fallback socket).
- **Makna status**:
  - `open`: host menerima koneksi TCP (SYN/ACK) → service merespons.
  - `closed`: host reachable tapi port tidak ada listener (RST dikirim).
  - `filtered`: paket diblokir/timeout (firewall/WAF), jadi status pasti tidak diketahui.

## SQLi Scanner
- **Manual probe**: `httpx` GET dengan payload preset (error/union/blind), cek error DB, delta ukuran respons, dan timing (blind).
- **Tool eksternal**: `nuclei -tags sqli` (+ template lokal jika ada) untuk melengkapi temuan otomatis.
- **Alasan**: menggabungkan heuristik cepat (tanpa tool) dengan template siap pakai supaya hasil tetap ada walau nuclei tak terpasang.
- **Output**: tabel payload vs hasil, log command nuclei, risk score berdasar severity tertinggi / error / blind timing.

## XSS Scanner
- **Tool utama**: `dalfox url <target> --format json` untuk fuzzing XSS modern.
- **Tool tambahan**: `nuclei` (template XSS lokal atau `-tags xss`) untuk signature-based detection.
- **Alasan**: Dalfox unggul untuk reflected XSS, nuclei melapisi template umum. Jika Dalfox/nuclei absen, hasil tetap mencatat kegagalan di log.
- **Output**: temuan gabungan yang didedup, risk score gabungan (count + worst severity), rekomendasi CSP/encoding.

## Header Analyzer
- **Fetch dasar**: `httpx` GET untuk membaca header live.
- **Tool eksternal**: `nmap --script http-security-headers,http-headers,http-methods` bila tersedia.
- **Alasan**: nmap NSE memberi header ekstra/insight metode HTTP; fallback httpx tetap jalan tanpa nmap.
- **Logika**: 12 header keamanan diberi weight; status Missing/Weak/Good dihitung jadi skor; risk = 100 - coverage + penalti header kritikal yang hilang.
- **Nmap NSE yang dipakai**:
  - `http-security-headers`: memeriksa header CSP/HSTS/XFO, dsb.
  - `http-headers`: dump header respon standar.
  - `http-methods`: enumerasi metode yang diizinkan.
  - Flag tambahan: `-sS` (SYN), `-Pn` (skip ping), `-p <port>` (target port), `--script-args http.useragent=...` (set UA), `--host-timeout` untuk batas waktu.

## Directory Buster
- **Tool utama**: `ffuf -u <base>/FUZZ -w <wordlist> -of json -fc 404`.
- **Fallback**: loop HTTP `httpx` dengan mini-wordlist bawaan kalau ffuf/wordlist tidak ada.
- **Alasan**: ffuf cepat, JSON mudah diolah; fallback memastikan fitur tidak mati.
- **Output**: daftar path + status/size, risk score berdasar kode signifikan (200/204/401/403/3xx/405), rekomendasi pakai wordlist lain.
- **Flag ffuf**:
  - `-u`: URL target, `FUZZ` akan diganti entri wordlist.
  - `-w`: path file wordlist.
  - `-of json`: output format JSON (diparse backend).
  - `-fc 404`: filter status 404 (abaikan “not found”).
  - `-t 80`: jumlah thread (default di kode).

## OSINT Hub
- **Phone**: `phoneinfoga`, `phonenumbers` (library), `truecaller` (scraper/cookie), `ignorant` (opsional), fallback deterministic metadata.
- **Domain**: `whois` CLI, plus parsing hasil ke detail registrar/created/expires/nameserver/status.
- **Email**: `holehe` CLI untuk cek keberadaan akun; fallback breach/disposable/gravatar.
- **Username**: `ignorant` (atau fallback deterministic count).
- **Alasan**: kombinasikan alat OSINT nyata bila ada; bila tidak, mock tetap konsisten untuk keperluan demo/lab.
- **Output**: daftar tool_outputs dengan kode +/−/x/!, summary_text, confidence High/Medium/Low.

## Credential Audit
- **Deteksi hash**: modul `hash_detector.py` (pattern-based) + opsi `hashid`/`hash-identifier` jika tersedia.
- **Cracking**: `john` dan `hashcat` dipanggil jika terpasang; juga rainbow table mini untuk hash umum.
- **Analitik plaintext**: entropy, pola keyboard/tanggal/dictionary, reuse antar user.
- **Alasan**: gabungkan analisis heuristik cepat dengan tool cracking nyata untuk hasil realistis.
- **Output**: weak/reused list, hash_analysis (tipe, crackability), crackable_hashes, policy coverage, rekomendasi spesifik (JtR/hashcat commands).

## Surface Auditor (web surface)
- **Tool utama**: `nuclei` (template HTTP; prefer path lokal jika ada).
- **Tambahan**: `nikto` untuk baseline vuln HTTP, `ffuf` untuk brute dir jika wordlist tersedia.
- **Alasan**: kombinasi passive+active cepat; jika salah satu tool hilang status dicatat sebagai skipped/error.
- **Output**: vulnerabilities gabungan, spider (dari ffuf), summary per tool & severity, risk score agregat.

## Wappalyzer
- **Tool utama**: `wappy` CLI (Wappalyzer) dengan output JSON sementara.
- **Fallback**: fingerprint manual via `httpx` (Server/X-Powered-By, konten HTML untuk CMS/JS lib).
- **Alasan**: tetap memberi teknologi terdeteksi meski wappy tidak terpasang atau output gagal di-parse.
- **Output**: mapping kategori → teknologi (nama, versi), total_found, timestamp.

---

Catatan tambahan:
- Semua perintah tool dijalankan dengan timeout wajar agar API tidak ngegantung.
- Jika tool tidak ada, respons tetap valid (status skipped/error dicatat di logs) sehingga frontend tidak blank.
- History/analytics tersimpan per-user (berbasis cookie) lewat file JSON, jadi hasil mock tetap terasa “persisten” tanpa database eksternal.***
