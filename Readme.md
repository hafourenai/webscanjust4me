# 🍯 HONEY Vulnerability Scanner

## 📁 Struktur Project
```
├── honey_scanner/    
│   ├── core/          
│   ├── detection/     
│   ├── antiban/       
│   ├── reporting/     
│   └── resources/     
├── reports/        
├── logs/              
├── config.yaml        
├── pyproject.toml              
```

## Instalasi & Penggunaan


### Setup Environment
### Lokal (Python)
```bash
# Install sebagai package lokal
pip install .

# Jalankan scanner
python honey.py <target_url> [options]
```

### 1. Basic Vulnerability Scan
```bash
# For learning/testing
python honey.py https://testphp.vulnweb.com
```

### 2. Stealth Scan (Production Sites)
```bash
python honey.py http://target.com --stealth --depth 7 --threads 10 --rate 0.5
```

### 3. Scan with Proxy Protection
```bash
python honey.py http://target.com --proxy-file proxies.txt --stealth --rate 0.5
```

### 4. Maximum Anonymity (TOR + Proxies)
```bash
# Start TOR
sudo service tor start

python honey.py http://target.com --proxy-file proxies.txt --use-tor --stealth --rate 0.2 -d 5

# Stop TOR
sudo service tor stop
```

### 5. Aggressive Bug Bounty Scan
```bash
python honey.py http://target.com --aggressive --threads 20 --depth 10 --rate 2.0
```

### 6. High-Value Target (Cloudflare/WAF)
```bash
python honey.py http://target.com --proxy-file proxies.txt --use-tor --stealth --rate 0.1 --threads 3 -d 3
```


#### **Clean**
```bash
python clean.py
```
### Opsi Command Line
- `-t, --threads`: Jumlah thread (default: 15).
- `-d, --depth`: Kedalaman crawling (default: 5).
- `--stealth`: Mode senyap (delay antar request lebih lama).
- `--aggressive`: Mode agresif (delay minimal).
- `--proxy-file`: Path ke file list proxy.
- `--use-tor`: Gunakan jaringan TOR.
- `--rate`: Batasi request per detik (e.g., `--rate 1.0`).
---

> [!IMPORTANT]
> **Legal Disclaimer:** Gunakan tools ini hanya untuk tujuan edukasi dan pengujian keamanan yang sah secara hukum. Penyalahgunaan terhadap target tanpa izin tertulis adalah sepenuhnya tanggung jawab pengguna.
