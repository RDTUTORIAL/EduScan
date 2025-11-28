# EduScan - Cybersecurity Learning Platform

<p align="center">
  <img src="https://img.shields.io/badge/Version-2.0.0-blue.svg" />
  <img src="https://img.shields.io/badge/React-18.x-61DAFB.svg" />
  <img src="https://img.shields.io/badge/FastAPI-0.100+-00a3a3.svg" />
  <img src="https://img.shields.io/badge/License-MIT-green.svg" />
</p>

<p align="center">
  <strong>🎯 Educational cybersecurity scanning platform with real-world tool integration</strong><br>
  A comprehensive web-based security testing suite for learning ethical hacking and penetration testing
</p>

---

## 🌏 Language / Bahasa
- [English](#english)
- [Bahasa Indonesia](#bahasa-indonesia)

---

# English

## 📖 Overview

EduScan is a modern web-based cybersecurity platform designed for educational purposes. It provides a comprehensive suite of security testing tools with an intuitive dashboard, making it perfect for learning ethical hacking, penetration testing, and security assessment methodologies.

### ✨ Key Features

- 🔍 **Port Scanner** - Network reconnaissance and service detection
- 🛡️ **SQL Injection Scanner** - Database vulnerability assessment with Nuclei integration
- 🚨 **XSS Scanner** - Cross-site scripting vulnerability detection with Dalfox
- 🔒 **Header Analyzer** - HTTP security headers analysis with nmap NSE scripts
- 📁 **Directory Buster** - Web directory and file discovery with ffuf/dirb
- 🔎 **OSINT Hub** - Open source intelligence gathering tools
- 🔑 **Credential Audit** - Password security analysis
- 📊 **Scan History** - Persistent storage with pagination and user sessions
- 🎨 **Modern UI** - Dark theme with responsive design

### 🏗️ Architecture

- **Frontend**: React 18 + Tailwind CSS + Framer Motion
- **Backend**: FastAPI with real tool integration
- **Database**: JSON file-based storage with user sessions
- **Security Tools**: Nuclei, Dalfox, nmap, ffuf, dirb, nikto
- **Password Tools**: John the Ripper, Hashcat, HashID
- **OSINT Tools**: Holehe, PhoneInfoga, Ignorant, Truecaller API
- **Network Tools**: whois, nmap NSE scripts

## 🚀 Quick Start

### Prerequisites

- **Node.js** 16+ and npm
- **Python** 3.8+
- **Go** 1.19+ (for security tools)

### 1. Clone Repository

```bash
git clone <repository-url>
cd eduscan
```

### 2. Frontend Setup

```bash
npm install
cp .env.example .env
# Edit .env if needed (default API: /api via CRA proxy)
npm start
```

The frontend will be available at `http://localhost:3000`

### 3. Backend Setup

```bash
cd server
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

The API will be available at `http://localhost:8000`

### 4. Install Security Tools

#### Ubuntu/Debian:
```bash
# Basic system tools
sudo apt update
sudo apt install python3-pip nmap nikto dirb whois

# Password cracking tools
sudo apt install john hashcat hashid

# Python OSINT tools  
pip3 install holehe phoneinfoga

# Go-based tools
go install github.com/hahwul/dalfox/v2@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/ffuf/ffuf@latest

# Social media OSINT (optional)
pip3 install ignorant

# Update nuclei templates
nuclei -update-templates
```

#### macOS:
```bash
# Using Homebrew
brew install nmap nikto dirb whois john-jumbo hashcat go

# Python tools
pip3 install holehe phoneinfoga ignorant

# Go tools
go install github.com/hahwul/dalfox/v2@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/ffuf/ffuf@latest

# Update templates
nuclei -update-templates
```

#### Windows:
```powershell
# Download and install manually:
# - Go: https://golang.org/dl/
# - nmap: https://nmap.org/download.html
# - John the Ripper: https://www.openwall.com/john/
# - Hashcat: https://hashcat.net/hashcat/

# Python tools
pip install holehe phoneinfoga ignorant

# Go tools
go install github.com/hahwul/dalfox/v2@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest  
go install github.com/ffuf/ffuf@latest

# Update templates
nuclei.exe -update-templates
```

#### Verify Installation:
```bash
# Core network tools
which nmap nuclei dalfox ffuf nikto dirb whois

# Password tools  
which john hashcat hashid

# OSINT tools
which holehe phoneinfoga ignorant

# Check versions
nuclei -version
john --list=formats | head -5
hashcat --version
```

## 🔧 Configuration

### Environment Variables

Create `.env` file in the root directory:

```bash
# Frontend Configuration
REACT_APP_API_BASE_URL=/api   # Use CRA proxy; works with ngrok tunneling to the frontend
# REACT_APP_API_BASE_URL=http://localhost:8000/api   # Use this if you deploy the backend separately

# Backend Configuration (optional)
EDUSCAN_DEBUG=true
EDUSCAN_CORS_ORIGINS=http://localhost:3000
```

### Tool Paths

Ensure all tools are in your PATH:

```bash
# Verify installations
which nmap
which nuclei
which dalfox
which ffuf
which nikto
which dirb
```

## 📁 Project Structure

```
eduscan/
├── src/                      # React frontend
│   ├── components/          # Reusable UI components
│   ├── pages/              # Scanner pages
│   ├── context/            # React context providers
│   └── utils/              # API client and helpers
├── server/                  # FastAPI backend
│   ├── app/
│   │   ├── api/            # API routes
│   │   ├── services/       # Tool integrations
│   │   ├── database.py     # JSON database manager
│   │   └── middleware.py   # Cookie management
├── public/                 # Static assets
└── docs/                   # Documentation
```

## 🔌 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/health` | GET | API health check |
| `/api/port-scan` | POST | Network port scanning |
| `/api/sqli-scan` | POST | SQL injection testing |
| `/api/xss-scan` | POST | Cross-site scripting testing |
| `/api/header-analyzer` | POST | HTTP header security analysis |
| `/api/directory-buster` | POST | Directory/file discovery |
| `/api/osint` | POST | OSINT information gathering |
| `/api/credential-audit` | POST | Password security audit |
| `/api/wappalyzer` | POST | Technology fingerprinting |
| `/api/history` | GET | Paginated scan history |
| `/api/history` | POST | Add custom history entry |
| `/api/history` | DELETE | Clear all history entries |
| `/api/history/{entry_id}` | DELETE | Delete a specific history record |
| `/api/user/stats` | GET | User statistics |
| `/api/scan-history` | GET | Legacy scan history alias |

## 🛡️ Security & Ethics

**⚠️ IMPORTANT**: This tool is for educational purposes only. Always ensure you have explicit written permission before scanning any systems. Use responsibly and in accordance with applicable laws and regulations.

### Ethical Guidelines

1. Only scan systems you own or have explicit permission to test
2. Respect rate limits and avoid overwhelming target systems
3. Use in isolated lab environments when possible
4. Follow responsible disclosure for any vulnerabilities found
5. Comply with all applicable laws and regulations

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

# Bahasa Indonesia

## 📖 Gambaran Umum

EduScan adalah platform keamanan siber berbasis web modern yang dirancang untuk tujuan edukasi. Platform ini menyediakan rangkaian lengkap alat pengujian keamanan dengan dashboard yang intuitif, membuatnya sempurna untuk mempelajari ethical hacking, penetration testing, dan metodologi penilaian keamanan.

### ✨ Fitur Utama

- 🔍 **Port Scanner** - Reconnaissance jaringan dan deteksi layanan
- 🛡️ **SQL Injection Scanner** - Penilaian kerentanan database dengan integrasi Nuclei
- 🚨 **XSS Scanner** - Deteksi kerentanan cross-site scripting dengan Dalfox
- 🔒 **Header Analyzer** - Analisis header keamanan HTTP dengan skrip nmap NSE
- 📁 **Directory Buster** - Penemuan direktori dan file web dengan ffuf/dirb
- 🔎 **OSINT Hub** - Alat pengumpulan intelijen sumber terbuka
- 🔑 **Credential Audit** - Analisis keamanan password
- 📊 **Riwayat Scan** - Penyimpanan persisten dengan paginasi dan sesi pengguna
- 🎨 **UI Modern** - Tema gelap dengan desain responsif

### 🏗️ Arsitektur

- **Frontend**: React 18 + Tailwind CSS + Framer Motion
- **Backend**: FastAPI dengan integrasi tool nyata
- **Database**: Penyimpanan berbasis file JSON dengan sesi pengguna
- **Security Tools**: Nuclei, Dalfox, nmap, ffuf, dirb, nikto
- **Password Tools**: John the Ripper, Hashcat, HashID
- **OSINT Tools**: Holehe, PhoneInfoga, Ignorant, Truecaller API
- **Network Tools**: whois, nmap NSE scripts

## 🚀 Memulai Cepat

### Prasyarat

- **Node.js** 16+ dan npm
- **Python** 3.8+
- **Go** 1.19+ (untuk security tools)

### 1. Clone Repository

```bash
git clone <repository-url>
cd eduscan
```

### 2. Setup Frontend

```bash
npm install
cp .env.example .env
# Edit .env jika diperlukan (API default: /api lewat proxy CRA)
npm start
```

Frontend akan tersedia di `http://localhost:3000`

### 3. Setup Backend

```bash
cd server
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

API akan tersedia di `http://localhost:8000`

### 4. Install Security Tools

#### Ubuntu/Debian:
```bash
# Tools sistem dasar
sudo apt update
sudo apt install python3-pip nmap nikto dirb whois

# Tools password cracking
sudo apt install john hashcat hashid

# Python OSINT tools  
pip3 install holehe phoneinfoga

# Go-based tools
go install github.com/hahwul/dalfox/v2@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/ffuf/ffuf@latest

# Social media OSINT (opsional)
pip3 install ignorant

# Update nuclei templates
nuclei -update-templates
```

#### macOS:
```bash
# Menggunakan Homebrew
brew install nmap nikto dirb whois john-jumbo hashcat go

# Python tools
pip3 install holehe phoneinfoga ignorant

# Go tools
go install github.com/hahwul/dalfox/v2@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/ffuf/ffuf@latest

# Update templates
nuclei -update-templates
```

#### Windows:
```powershell
# Download dan install manual:
# - Go: https://golang.org/dl/
# - nmap: https://nmap.org/download.html
# - John the Ripper: https://www.openwall.com/john/
# - Hashcat: https://hashcat.net/hashcat/

# Python tools
pip install holehe phoneinfoga ignorant

# Go tools
go install github.com/hahwul/dalfox/v2@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest  
go install github.com/ffuf/ffuf@latest

# Update templates
nuclei.exe -update-templates
```

#### Verifikasi Instalasi:
```bash
# Core network tools
which nmap nuclei dalfox ffuf nikto dirb whois

# Password tools  
which john hashcat hashid

# OSINT tools
which holehe phoneinfoga ignorant

# Cek versi
nuclei -version
john --list=formats | head -5
hashcat --version
```

## 🔧 Konfigurasi

### Environment Variables

Buat file `.env` di direktori root:

```bash
# Konfigurasi Frontend
REACT_APP_API_BASE_URL=/api   # Gunakan proxy CRA; cocok untuk ngrok ke frontend
# REACT_APP_API_BASE_URL=http://localhost:8000/api   # Pakai ini jika backend dipisah

# Konfigurasi Backend (opsional)
EDUSCAN_DEBUG=true
EDUSCAN_CORS_ORIGINS=http://localhost:3000
```

### Path Tool

Pastikan semua tool ada di PATH Anda:

```bash
# Verifikasi instalasi
which nmap
which nuclei
which dalfox
which ffuf
which nikto
which dirb
```

## 📁 Struktur Proyek

```
eduscan/
├── src/                      # React frontend
│   ├── components/          # Komponen UI yang dapat digunakan kembali
│   ├── pages/              # Halaman scanner
│   ├── context/            # React context providers
│   └── utils/              # API client dan helpers
├── server/                  # FastAPI backend
│   ├── app/
│   │   ├── api/            # Route API
│   │   ├── services/       # Integrasi tool
│   │   ├── database.py     # Manager database JSON
│   │   └── middleware.py   # Manajemen cookie
├── public/                 # Asset statis
└── docs/                   # Dokumentasi
```

## 🔌 Endpoint API

| Endpoint | Method | Deskripsi |
|----------|--------|-----------|
| `/api/health` | GET | Cek status API |
| `/api/port-scan` | POST | Scanning port jaringan |
| `/api/sqli-scan` | POST | Pengujian SQL injection |
| `/api/xss-scan` | POST | Pengujian cross-site scripting |
| `/api/header-analyzer` | POST | Analisis keamanan header HTTP |
| `/api/directory-buster` | POST | Penemuan direktori/file |
| `/api/osint` | POST | Pengumpulan informasi OSINT |
| `/api/credential-audit` | POST | Audit keamanan password |
| `/api/wappalyzer` | POST | Fingerprint teknologi |
| `/api/history` | GET | Riwayat scan dengan paginasi |
| `/api/history` | POST | Tambah entri riwayat manual |
| `/api/history` | DELETE | Hapus seluruh riwayat |
| `/api/history/{entry_id}` | DELETE | Hapus entri riwayat tertentu |
| `/api/user/stats` | GET | Statistik pengguna |
| `/api/scan-history` | GET | Endpoint legacy riwayat scan |

## 🛡️ Keamanan & Etika

**⚠️ PENTING**: Tool ini hanya untuk tujuan edukasi. Selalu pastikan Anda memiliki izin tertulis eksplisit sebelum memindai sistem apa pun. Gunakan dengan bertanggung jawab dan sesuai dengan hukum dan regulasi yang berlaku.

### Panduan Etika

1. Hanya scan sistem yang Anda miliki atau memiliki izin eksplisit untuk diuji
2. Hormati batas rate dan hindari membebani sistem target
3. Gunakan di lingkungan lab terisolasi jika memungkinkan
4. Ikuti responsible disclosure untuk kerentanan yang ditemukan
5. Patuhi semua hukum dan regulasi yang berlaku

## 🤝 Berkontribusi

1. Fork repository
2. Buat branch fitur (`git checkout -b feature/fitur-luar-biasa`)
3. Commit perubahan Anda (`git commit -m 'Tambah fitur luar biasa'`)
4. Push ke branch (`git push origin feature/fitur-luar-biasa`)
5. Buka Pull Request

## 📄 Lisensi

Proyek ini dilisensikan di bawah MIT License - lihat file LICENSE untuk detailnya.

---

## 🔗 Links

- **Live Demo**: [Coming Soon]
- **Documentation**: [Wiki](./docs/)
- **Issues**: [GitHub Issues](https://github.com/your-repo/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-repo/discussions)

## 💬 Support

Jika Anda memiliki pertanyaan atau memerlukan bantuan:

1. Baca dokumentasi terlebih dahulu
2. Periksa [Issues](https://github.com/your-repo/issues) yang ada
3. Buat issue baru dengan template yang sesuai
4. Bergabunglah dengan [Discussions](https://github.com/your-repo/discussions)

---

<p align="center">
  <strong>Made with ❤️ for the cybersecurity community</strong><br>
  <em>Happy ethical hacking! 🛡️</em>
</p>
