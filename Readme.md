# 🍯 HONEY Vulnerability Scanner

## Perbaikan

-  Advanced WAF Bypass Engine
-  ML False Positive Reducer

## Struktur Project

```
honey_scanner/
  ├── core/            # Engine utama & fingerprinting
  ├── detection/       # Analyzer & verifikasi vulnerabilites
  ├── antiban/         # Proxy & rate limiting
  ├── reporting/       # Sistem pelaporan multi-format
  └── main.py          # Entry point utama
```

## Instalasi & Penggunaan

```bash
# Clone repository
git clone https://github.com/hafourenai/webscanjust4me
cd webscanjust4me

# Install dependencies
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Cara Menggunakan

```powershell
python main.py <target_url> [options]
```

#### **1. Basic Vulnerability Scan**
```bash
# For learning/testing
python main.py https://testphp.vulnweb.com
```

#### **2. Stealth Scan (Production Sites)**
```bash
python main.py http://target.com --stealth --depth 7 --threads 10 --rate 0.5
```

#### **3. Scan with Proxy Protection**
```bash
python main.py http://target.com --proxy-file proxies.txt --stealth --rate 0.5
```
#### **4. Maximum Anonymity (TOR + Proxies)**
```bash
# Start TOR
sudo service tor start

python main.py http://target.com --proxy-file proxies.txt --use-tor --stealth --rate 0.2 -d 5

# Stop TOR
sudo service tor stop
```

#### **5. Aggressive Bug Bounty Scan**
```bash
python main.py http://target.com --aggressive --threads 20 --depth 10 --rate 2.0
```

#### **6. High-Value Target (Cloudflare/WAF)**
```bash
python main.py http://target.com --proxy-file proxies.txt --use-tor --stealth --rate 0.1 --threads 3 -d 3
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
> Gunakan tools ini hanya untuk tujuan edukasi dan pengujian keamanan legal. Penggunaan terhadap target tanpa izin adalah ilegal.
