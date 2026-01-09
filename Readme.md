# 🍯 HONEY Vulnerability Scanner

## Fitur 

### 1. Deteksi Vulnerability Dasar
- **SQL Injection (SQLi)**: 
    - Deteksi berbasis error dengan 25+ pola spesifik database (MySQL, PostgreSQL, MSSQL, Oracle, SQLite).
    - Boolean-based analysis dengan threshold perbedaan konten yang ketat.
    - Time-based analysis menggunakan verifikasi statistik dan baseline timing.
    - Suppport Union-based, DNS Exfiltration, dan Out-of-Band (OOB).
- **Cross-Site Scripting (XSS)**: 
    - *Context-aware analysis* untuk menentukan lokasi injeksi (Script, Attribute, Tag, SVG, MathML).
    - Deteksi encoding cerdas (HTML entities, URL encoding, Unicode, double encoding).
    - Verifikasi multi-vector untuk memastikan eksploitabilitas.
- **Local File Inclusion (LFI)**: 
    - Verifikasi konten file dengan pola sekunder (e.g., `root:` + `bin:`).
    - Pengurangan false positive dengan deteksi halaman error dan dokumentasi.
- **CSRF Detection**: 
    - Deteksi multi-layer (Token, SameSite, Custom Headers).
    - Analisis kualitas token (Entropy & Length).
    - *Active testing* (test tanpa token, token invalid, dll).

### 2. Anti-Ban System
- **Proxy Rotation**: Mendukung penggunaan list proxy HTTP/S.
- **TOR Integration**: Integrasi langsung dengan jaringan TOR untuk anonimitas maksimal.
- **Rate Limiting**: Kontrol jumlah request per detik secara presisi.
- **Smart Block Detection**: Mendeteksi blokir (403, 429, Captcha) dan otomatis menyesuaikan perilaku.


---

## Instalasi & Penggunaan

```bash
# Clone repository
git clone https://github.com/hafourenai/webscanjust4me
cd webscanjust4me

python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Cara Menggunakan
```powershell
python honey.py <target_url> [options]
```

#### **1. Basic Vulnerability Scan**
```bash
# For learning/testing
python honey.py https://testphp.vulnweb.com
```

#### **2. Stealth Scan (Production Sites)**
```bash
python honey.py http://target.com --stealth --depth 7 --threads 10 --rate 0.5
```

#### **3. Scan with Proxy Protection**
```bash
python honey.py http://target.com --proxy-file proxies.txt --stealth --rate 0.5
```
#### **4. Maximum Anonymity (TOR + Proxies)**
```bash
# Start TOR
sudo service tor start

python honey.py http://target.com --proxy-file proxies.txt --use-tor --stealth --rate 0.2 -d 5

# Stop TOR
sudo service tor stop
```

#### **5. Aggressive Bug Bounty Scan**
```bash
python honey.py http://target.com --aggressive --threads 20 --depth 10 --rate 2.0
```

#### **6. High-Value Target (Cloudflare/WAF)**
```bash
python honey.py http://target.com --proxy-file proxies.txt --use-tor --stealth --rate 0.1 --threads 3 -d 3
```

### Opsi Command Line
- `-t, --threads`: Jumlah thread (default: 15).
- `-d, --depth`: Kedalaman crawling (default: 5).
- `--stealth`: Mode senyap (delay antar request lebih lama).
- `--aggressive`: Mode agresif (delay minimal).
- `--proxy-file`: Path ke file list proxy.
- `--use-tor`: Gunakan jaringan TOR.
- `--rate`: Batasi request per detik (e.g., `--rate 2.0` untuk 2 req/s).

---

## Maintenance
Gunakan script pembersih untuk menjaga performa tools:
```powershell
python cleanup_pycache.py
```

---
> [!IMPORTANT]
> Gunakan tools ini hanya untuk tujuan edukasi dan pengujian keamanan legal. Penggunaan terhadap target tanpa izin adalah ilegal.
